package honeybadgerbft

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"github.com/Nik-U/pbc"
	"github.com/golang/protobuf/proto"

	cb "github.com/hyperledger/fabric/protos/common"
	ab "github.com/hyperledger/fabric/protos/orderer"
	"github.com/hyperledger/fabric/protos/utils"
)

type HoneyBadgerBlock struct {
	total         int
	maxMalicious  int
	channel       chan *ab.HoneyBadgerBFTMessage
	broadcastFunc func(msg *ab.HoneyBadgerBFTMessageThresholdEncryption)
	keys          *TPKEKeys
	acs           *CommonSubset

	In  chan []*cb.Envelope
	Out chan []*cb.Envelope
}

func NewHoneyBadgerBlock(total int, maxMalicious int, receiveMessageChannel chan *ab.HoneyBadgerBFTMessage, broadcastFunc func(msg ab.HoneyBadgerBFTMessage), keys *TPKEKeys, acs *CommonSubset) (result *HoneyBadgerBlock) {
	bc := func(msg *ab.HoneyBadgerBFTMessageThresholdEncryption) {
		broadcastFunc(ab.HoneyBadgerBFTMessage{Type: &ab.HoneyBadgerBFTMessage_ThresholdEncryption{ThresholdEncryption: msg}})
	}
	result = &HoneyBadgerBlock{
		total:         total,
		maxMalicious:  maxMalicious,
		channel:       receiveMessageChannel,
		broadcastFunc: bc,
		keys:          keys,
		acs:           acs,

		In:  make(chan []*cb.Envelope),
		Out: make(chan []*cb.Envelope),
	}
	go result.honeyBadgerBlockService()
	return result
}

func (block *HoneyBadgerBlock) honeyBadgerBlockService() {
	// TODO: check that propose_in is the correct length, not too large
	committingBatch := <-block.In
	logger.Debugf("BLOCK input: []*cb.Envelop(len=%v)", len(committingBatch))

	proposal, err := encodeTransactions(committingBatch)
	if err != nil {
		logger.Panic(err)
	}
	key := aesGenKey()
	ciphered, err := aesEncrypt(proposal, key)
	if err != nil {
		logger.Panicf("AES encrypt error: %s", err)
	}
	U, V, W, err := block.keys.Encrypt(key)
	if err != nil {
		logger.Panic(err)
	}

	toACS := encodeByteArrays([][]byte{encodeUVW(U, V, W), ciphered})
	block.acs.In <- toACS

	fromACS := <-block.acs.Out
	if len(fromACS) != block.total {
		logger.Panicf("Wrong number of acs output")
	}
	count := 0
	for _, v := range fromACS {
		if v != nil {
			count++
		}
	}
	if count < block.total-block.maxMalicious {
		logger.Panicf("Wrong number of acs valid output")
	}

	var shareMsgs []*ab.HoneyBadgerBFTMessageThresholdEncryptionShare
	for i := 0; i < block.total; i++ {
		v := fromACS[uint64(i)]
		var shareMsgPayload []byte
		if v == nil {
			shareMsgPayload = []byte{}
		} else {
			d, err := decodeByteArrays(v)
			if err != nil {
				logger.Panic(err)
			}
			U, V, W, err := decodeUVW(block.keys, d[0])
			if err != nil {
				logger.Panic(err)
			}
			shareMsg, err := block.keys.DecryptShare(U, V, W)
			if err != nil {
				logger.Panic(err)
			}
			shareMsgPayload = shareMsg.Bytes()
		}
		shareMsgs = append(shareMsgs, &ab.HoneyBadgerBFTMessageThresholdEncryptionShare{Payload: shareMsgPayload})
	}
	block.broadcastFunc(&ab.HoneyBadgerBFTMessageThresholdEncryption{Shares: shareMsgs})

	sharesReceived := make(map[int][]*pbc.Element)
	for len(sharesReceived) < block.maxMalicious+1 {
		msg := <-block.channel
		sender := int(msg.GetSender())
		shares := make([]*pbc.Element, block.total)
		for i, m := range msg.GetThresholdEncryption().GetShares() {
			d := m.GetPayload()
			if len(d) > 0 { //TODO: which is right?
				shares[i] = block.keys.NewG1AndSetBytes(d)
			} else {
				shares[i] = nil
			}
		}
		if sharesReceived[sender] != nil {
			logger.Debugf("Redudant decryption share from %v", sender)
			continue
		}
		sharesReceived[sender] = shares
	}
	// TODO: Accountability
	// If decryption fails at this point, we will have evidence of misbehavior,
	// but then we should wait for more decryption shares and try again
	var committedBatch []*cb.Envelope
	for i, v := range fromACS {
		if v == nil {
			continue
		}
		svec := make(map[int]*pbc.Element)
		for sender, shares := range sharesReceived {
			svec[sender] = shares[i]
		}
		d, err := decodeByteArrays(v)
		if err != nil {
			logger.Panic(err)
		}
		U, V, W, err := decodeUVW(block.keys, d[0])
		ciph := d[1]
		if err != nil {
			logger.Panic(err)
		}
		key, err := block.keys.CombineShares(svec, U, V, W)
		if err != nil {
			logger.Panic(err)
		}
		raw, err := aesDecrypt(ciph, key)
		if err != nil {
			logger.Panic(err)
		}
		transations, err := decodeTransactions(raw)
		if err != nil {
			logger.Panic(err)
		}
		committedBatch = append(committedBatch, transations...)
	}

	logger.Debugf("BLOCK output: []*cb.Envelop(len=%v)", len(committedBatch))
	block.Out <- committedBatch
}

//////////////////////////////////////////////////////////////////////////////////
//                                                                              //
//                                  TOOLS                                       //
//                                                                              //
//////////////////////////////////////////////////////////////////////////////////

func aesGenKey() []byte {
	rand.Seed(time.Now().Unix())
	result := make([]byte, 32) // Hardcoded
	for i := range result {
		result[i] = byte(rand.Int())
	}
	return result
}

func aesEncrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	data = pkcs5Padding(data, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(data))
	blockMode.CryptBlocks(crypted, data)
	return crypted, nil
}

func aesDecrypt(crypted []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	data := make([]byte, len(crypted))
	blockMode.CryptBlocks(data, crypted)
	data = pkcs5UnPadding(data)
	return data, nil
}

func pkcs5Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	paddata := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, paddata...)
}

func pkcs5UnPadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

func encodeByteArrays(arrays [][]byte) []byte {
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, int32(len(arrays)))
	for _, array := range arrays {
		binary.Write(buf, binary.BigEndian, int32(len(array)))
		buf.Write(array)
	}
	return buf.Bytes()
}

func decodeByteArrays(data []byte) ([][]byte, error) {
	buf := bytes.NewBuffer(data)
	var l int32
	err := binary.Read(buf, binary.BigEndian, &l)
	if err != nil {
		return nil, fmt.Errorf("Error occured when decoding transactions: %s", err)
	}
	result := make([][]byte, l)
	for i := int32(0); i < l; i++ {
		var ll int32
		err := binary.Read(buf, binary.BigEndian, &ll)
		if err != nil {
			return nil, fmt.Errorf("Error occured when decoding transactions: %s", err)
		}
		array := make([]byte, ll)
		n, err := buf.Read(array)
		if err != nil {
			return nil, fmt.Errorf("Error occured when decoding transactions: %s", err)
		}
		if int32(n) != ll {
			return nil, fmt.Errorf("Error occured when decoding transactions: length mismatch")
		}
		result[i] = array
	}
	if len(buf.Bytes()) > 0 {
		return nil, fmt.Errorf("Error occured when decoding transactions: total length mismatch")
	}
	return result, nil
}

func encodeTransactions(transactions []*cb.Envelope) ([]byte, error) {
	var arrays = make([][]byte, len(transactions))
	for i, tx := range transactions {
		array, err := utils.Marshal(tx)
		arrays[i] = array
		if err != nil {
			return nil, err
		}
	}
	return encodeByteArrays(arrays), nil
}

func decodeTransactions(data []byte) ([]*cb.Envelope, error) {
	arrays, err := decodeByteArrays(data)
	if err != nil {
		return nil, err
	}
	var transactions = make([]*cb.Envelope, len(arrays))
	for i, array := range arrays {
		tx := new(cb.Envelope)
		err := proto.Unmarshal(array, tx)
		if err != nil {
			return nil, err
		}
		transactions[i] = tx
	}
	return transactions, nil
}

func encodeUVW(U *pbc.Element, V []byte, W *pbc.Element) []byte {
	var arrays = make([][]byte, 3)
	arrays[0] = U.Bytes()
	arrays[1] = V
	arrays[2] = W.Bytes()
	return encodeByteArrays(arrays)
}

func decodeUVW(k *TPKEKeys, data []byte) (U *pbc.Element, V []byte, W *pbc.Element, err error) {
	arrays, err := decodeByteArrays(data)
	if len(arrays) != 3 {
		return nil, nil, nil, fmt.Errorf("Error occured when decoding UVW: wrong # of elements")
	}
	U = k.NewG2AndSetBytes(arrays[0])
	V = arrays[1]
	W = k.NewG2AndSetBytes(arrays[2])
	return U, V, W, nil
}
