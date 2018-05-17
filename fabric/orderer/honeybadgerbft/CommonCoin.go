package honeybadgerbft

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"github.com/Nik-U/pbc"

	ab "github.com/hyperledger/fabric/protos/orderer"
)

type CommonCoin struct {
	instanceIndex int
	tolerance     int
	channel       chan *ab.HoneyBadgerBFTMessage
	broadcastFunc func(msg *ab.HoneyBadgerBFTMessageCommonCoin)
	keys          *TBLSKeys

	results map[uint64]chan bool
	lock    sync.Mutex
	exit    chan interface{}
}

func NewCommonCoin(instanceIndex int, tolerance int, receiveMessageChannel chan *ab.HoneyBadgerBFTMessage, broadcastFunc func(msg ab.HoneyBadgerBFTMessage), keys *TBLSKeys) (result *CommonCoin) {
	bc := func(msg *ab.HoneyBadgerBFTMessageCommonCoin) {
		broadcastFunc(ab.HoneyBadgerBFTMessage{Type: &ab.HoneyBadgerBFTMessage_CommonCoin{CommonCoin: msg}})
	}
	result = &CommonCoin{
		instanceIndex: instanceIndex,
		tolerance:     tolerance,
		channel:       receiveMessageChannel,
		broadcastFunc: bc,
		keys:          keys,

		results: make(map[uint64]chan bool),
		exit:    make(chan interface{}),
	}
	go result.commonCoinService()
	return result
}

func (coin *CommonCoin) getResultChannel(round uint64) (result chan bool) {
	coin.lock.Lock()
	defer coin.lock.Unlock()
	result, exist := coin.results[round]
	if !exist {
		result = make(chan bool)
		coin.results[round] = result
	}
	return result
}

func (coin *CommonCoin) commonCoinService() {
	var received = make(map[uint64]map[int]*pbc.Element)
	for {
		select {
		case <-coin.exit:
			//logger.Debugf("COIN[%v] receive service exit", coin.instanceIndex)
			return
		case msg := <-coin.channel:
			sender := int(msg.GetSender())
			round := msg.GetCommonCoin().GetRound()
			if received[round] != nil && received[round][sender] != nil {
				logger.Debugf("Redundant coin message from %v", sender)
				continue
			}
			payload := msg.GetCommonCoin().GetPayload()
			signature := coin.keys.NewG1AndSetBytes(payload)
			bytesBuffer := bytes.NewBuffer([]byte{})
			binary.Write(bytesBuffer, binary.BigEndian, round)
			hash := coin.keys.HashMessage(bytesBuffer.Bytes())
			if !coin.keys.VerifyShare(signature, hash, sender) {
				logger.Debugf("Failed to verify share from %s at round %v", sender, round)
				continue
			}
			if received[round] == nil {
				received[round] = make(map[int]*pbc.Element)
			}
			received[round][sender] = signature
			if len(received[round]) == coin.tolerance+1 {
				combined := coin.keys.CombineShares(received[round])
				if !coin.keys.VerifySignature(combined, hash) {
					logger.Panicf("Faild to verify signature") //TODO: Or Debugf?
				}
				sha256Hash := sha256.New()
				sha256Hash.Write(combined.Bytes())
				if sha256Hash.Sum(nil)[0]&1 == 0 {
					coin.getResultChannel(round) <- false
				} else {
					coin.getResultChannel(round) <- true
				}
			}
		}
	}
}

func (coin *CommonCoin) Get(round uint64) bool {
	//logger.Debugf("COIN[%v][r=%v] start", coin.instanceIndex, round)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, round)
	coin.broadcastFunc(&ab.HoneyBadgerBFTMessageCommonCoin{
		Round:   round,
		Payload: coin.keys.Sign(coin.keys.HashMessage(bytesBuffer.Bytes())).Bytes(),
	})
	result := <-coin.getResultChannel(round)
	//logger.Debugf("COIN[%v][r=%v] output: %v", coin.instanceIndex, round, result)
	return result
}

func (coin *CommonCoin) Stop() {
	close(coin.exit)
}
