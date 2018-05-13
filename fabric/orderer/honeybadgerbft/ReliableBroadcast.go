package honeybadgerbft

import (
	"crypto/sha256"
	"fmt"
	"math"

	ab "github.com/hyperledger/fabric/protos/orderer"
	zfec "gitlab.com/zfec/go-zfec"
)

type ReliableBroadcast struct {
	instanceIndex int // == leaderIndex
	total         int
	maxMalicious  int
	ordererIndex  int
	leaderIndex   int
	channel       chan *ab.HoneyBadgerBFTMessage
	sendFunc      func(index int, msg *ab.HoneyBadgerBFTMessageReliableBroadcast)
	broadcastFunc func(msg *ab.HoneyBadgerBFTMessageReliableBroadcast)

	In  chan []byte
	Out chan []byte
}

func NewReliableBroadcast(instanceIndex int, total int, maxMalicious int, ordererIndex int, leaderIndex int, receiveMessageChannel chan *ab.HoneyBadgerBFTMessage, sendFunc func(index int, msg ab.HoneyBadgerBFTMessage), broadcastFunc func(msg ab.HoneyBadgerBFTMessage)) (result *ReliableBroadcast) {
	// TODO: check param relations
	s := func(index int, msg *ab.HoneyBadgerBFTMessageReliableBroadcast) {
		sendFunc(index, ab.HoneyBadgerBFTMessage{Type: &ab.HoneyBadgerBFTMessage_ReliableBroadcast{ReliableBroadcast: msg}})
	}
	bc := func(msg *ab.HoneyBadgerBFTMessageReliableBroadcast) {
		broadcastFunc(ab.HoneyBadgerBFTMessage{Type: &ab.HoneyBadgerBFTMessage_ReliableBroadcast{ReliableBroadcast: msg}})
	}
	result = &ReliableBroadcast{
		instanceIndex: instanceIndex,
		total:         total,
		maxMalicious:  maxMalicious,
		ordererIndex:  ordererIndex,
		leaderIndex:   leaderIndex,
		channel:       receiveMessageChannel,
		sendFunc:      s,
		broadcastFunc: bc,

		In:  make(chan []byte),
		Out: make(chan []byte),
	}
	go result.reliableBroadcastService()
	return result
}

func (rbc *ReliableBroadcast) reliableBroadcastService() {
	// K               = N - 2 * f  # Need this many to reconstruct
	// EchoThreshold   = N - f      # Wait for this many ECHO to send READY
	// ReadyThreshold  = f + 1      # Wait for this many READY to amplify READY
	// OutputThreshold = 2 * f + 1  # Wait for this many READY to output
	// # NOTE: The above thresholds  are chosen to minimize the size
	// # of the erasure coding stripes, i.e. to maximize K.
	// # The following alternative thresholds are more canonical
	// # (e.g., in Bracha '86) and require larger stripes, but must wait
	// # for fewer nodes to respond
	// #   EchoThreshold = ceil((N + f + 1.)/2)
	// #   K = EchoThreshold - f
	var K = rbc.total - 2*rbc.maxMalicious
	var EchoThreshold = rbc.total - rbc.maxMalicious
	var ReadyThreshold = rbc.maxMalicious + 1
	var OutputThreshold = 2*rbc.maxMalicious + 1
	z := zfecParam{K: K, M: rbc.total}

	if rbc.leaderIndex == rbc.ordererIndex {
		data := <-rbc.In
		logger.Debugf("RBC[%v] input: []bytes(len=%v)", rbc.instanceIndex, len(data))
		blocks, padlen, err := z.Encode(data)
		if err != nil {
			logger.Panicf("Error occured when encoding data: %s", err)
		}
		tree := newMerkleTree(blocks) //TODO: check whether full binary tree
		rootHash := tree[1]

		for i := 0; i < rbc.total; i++ {
			branch := getMerkleTreeBranch(tree, i)
			rbc.sendFunc(i, &ab.HoneyBadgerBFTMessageReliableBroadcast{Type: &ab.HoneyBadgerBFTMessageReliableBroadcast_Val{Val: &ab.HoneyBadgerBFTMessageReliableBroadcastVAL{}}, PadLength: uint64(padlen), Block: blocks[i], RootHash: rootHash, Branch: branch})
		}

	}
	// TODO: filter policy: if leader, discard all messages until sending VAL

	var rootHashFromLeader []byte
	var blocks = make(map[string][][]byte)
	var echoCounter = make(map[string]int)
	var echoSenders = make(map[int]bool)
	var ready = make(map[string]map[int]bool)
	var readySent bool
	var readySenders = make(map[int]bool)

	decodeAndVerifyAndOutput := func(rootHash []byte, padlen int) {
		data, err := z.Decode(blocks[string(rootHash)], padlen)
		if err != nil {
			logger.Panicf("Error occured when decoding data: , err")
		}
		tmpBlocks, tmpPadlen, err := z.Encode(data)
		if err != nil {
			logger.Panicf("Error occured when re-encoding data: %s", err)
		}
		if tmpPadlen != padlen {
			logger.Panicf("RBC[%v] Padlen mismatch", rbc.instanceIndex)
		}
		tmpTree := newMerkleTree(tmpBlocks)
		tmpRootHash := tmpTree[1]
		if string(tmpRootHash) != string(rootHash) { // TODO: Accountability: If this fails, incriminate leader
			logger.Panicf("RBC[%v] Verification failed", rbc.instanceIndex)
		} else {
			logger.Debugf("RBC[%v] output: []bytes(len=%v)", rbc.instanceIndex, len(data))
			rbc.Out <- data
		}
	}
	for {
		msg := <-rbc.channel
		sender := int(msg.GetSender())
		subMsg := msg.GetReliableBroadcast()
		rootHash := subMsg.GetRootHash()
		rootHashString := string(rootHash)
		branch := subMsg.GetBranch()
		block := subMsg.GetBlock()
		padlen := subMsg.GetPadLength()
		switch subMsg.Type.(type) {
		case *ab.HoneyBadgerBFTMessageReliableBroadcast_Val:
			if rootHashFromLeader != nil {
				continue
			}

			if sender != rbc.leaderIndex {
				logger.Panicf("VAL message from other than leader: %v", sender)
				continue
			}

			if !verifyMerkleTree(rootHash, branch, block, rbc.ordererIndex) {
				logger.Panicf("Failed to validate VAL message")
			}

			rootHashFromLeader = rootHash

			rbc.broadcastFunc(&ab.HoneyBadgerBFTMessageReliableBroadcast{Type: &ab.HoneyBadgerBFTMessageReliableBroadcast_Echo{Echo: &ab.HoneyBadgerBFTMessageReliableBroadcastECHO{}}, PadLength: padlen, Block: block, RootHash: rootHash, Branch: branch})

		case *ab.HoneyBadgerBFTMessageReliableBroadcast_Echo:
			if _, exist := blocks[rootHashString]; exist {
				if blocks[rootHashString][sender] != nil || echoSenders[sender] {
					logger.Debugf("Redundant ECHO")
					continue
				}
			} else {
				blocks[rootHashString] = make([][]byte, 8)
			}

			if !verifyMerkleTree(rootHash, branch, block, sender) {
				logger.Panicf("Failed to validate ECHO message")
			}

			blocks[rootHashString][sender] = block
			echoSenders[sender] = true
			echoCounter[rootHashString]++

			//logger.Infof("RBC INST %v received a ECHO message from %v; echoCounter[roothash]=%v of %v", rbc.leaderIndex, sender, echoCounter[rootHashString], EchoThreshold)
			if echoCounter[rootHashString] >= EchoThreshold && !readySent {
				rbc.broadcastFunc(&ab.HoneyBadgerBFTMessageReliableBroadcast{Type: &ab.HoneyBadgerBFTMessageReliableBroadcast_Ready{Ready: &ab.HoneyBadgerBFTMessageReliableBroadcastREADY{}}, RootHash: rootHash, PadLength: padlen})
				readySent = true
			}

			if len(ready[rootHashString]) >= OutputThreshold && echoCounter[rootHashString] >= K {
				decodeAndVerifyAndOutput(rootHash, int(padlen))
				return
			}

		case *ab.HoneyBadgerBFTMessageReliableBroadcast_Ready:
			_, exist := ready[rootHashString]
			if (exist && ready[rootHashString][sender]) || readySenders[sender] {
				logger.Debugf("Redundant READY")
				continue
			}

			if !exist {
				ready[rootHashString] = make(map[int]bool)
			}
			ready[rootHashString][sender] = true
			readySenders[sender] = true

			//logger.Infof("RBC INST %v received a READY message from %v; len(ready[rootHashString])=%v of %v", rbc.leaderIndex, sender, len(ready[rootHashString]), ReadyThreshold)
			if len(ready[rootHashString]) >= ReadyThreshold && !readySent {
				rbc.broadcastFunc(&ab.HoneyBadgerBFTMessageReliableBroadcast{Type: &ab.HoneyBadgerBFTMessageReliableBroadcast_Ready{Ready: &ab.HoneyBadgerBFTMessageReliableBroadcastREADY{}}, RootHash: rootHash, PadLength: padlen})
				readySent = true
			}

			if len(ready[rootHashString]) >= OutputThreshold && echoCounter[rootHashString] >= K {
				decodeAndVerifyAndOutput(rootHash, int(padlen))
				return
			}
		}
	}
}

//////////////////////////////////////////////////////////////////////////////////
//                                                                              //
//                                  TOOLS                                       //
//                                                                              //
//////////////////////////////////////////////////////////////////////////////////

type zfecParam struct { // TODO: this struct is redundant
	K int
	M int
}

func (z *zfecParam) Encode(data []byte) (blocks [][]byte, padlen int, err error) {
	zfecInstance, err := zfec.Init(z.K, z.M)
	if err != nil {
		return nil, 0, err
	}
	defer zfecInstance.Dealloc()
	return zfecInstance.EncodeBytes(data)
}

func (z *zfecParam) Decode(blocks [][]byte, padlen int) (data []byte, err error) {
	zfecInstance, err := zfec.Init(z.K, z.M)
	if err != nil {
		return nil, err
	}
	defer zfecInstance.Dealloc()
	var b [][]byte
	var l []int

	for i, v := range blocks {
		if v == nil {
			continue
		}
		l = append(l, i)
		b = append(b, v)
		if len(l) == z.K {
			break
		}
	}
	if len(l) != z.K {
		return nil, fmt.Errorf("No enough blocks, need %v have %v", z.K, len(l))
	}
	return zfecInstance.Decode(b, l, padlen)
}

func merkleTreeHash(data []byte, others ...[]byte) []byte { // NOTE: root at index=1
	s := sha256.New()
	s.Write(data)
	for _, d := range others {
		s.Write(d)
	}
	return s.Sum(nil)
}

func newMerkleTree(blocks [][]byte) [][]byte {
	bottomRow := int(math.Pow(2, math.Ceil(math.Log2(float64(len(blocks))))))
	result := make([][]byte, 2*bottomRow, 2*bottomRow)
	for i := 0; i < len(blocks); i++ {
		result[bottomRow+i] = merkleTreeHash(blocks[i])
	}
	for i := bottomRow - 1; i > 0; i-- {
		result[i] = merkleTreeHash(result[i*2], result[i*2+1])
	}
	return result
}

func getMerkleTreeBranch(tree [][]byte, index int) (result [][]byte) { // NOTE: index from 0, block index not tree item index
	t := index + (len(tree) >> 1)
	for t > 1 {
		result = append(result, tree[t^1])
		t /= 2
	}
	return result
}

func verifyMerkleTree(rootHash []byte, branch [][]byte, block []byte, index int) bool {
	//TODO: add checks
	tmp := merkleTreeHash(block)
	for _, node := range branch {
		if index&1 == 0 {
			tmp = merkleTreeHash(tmp, node)
		} else {
			tmp = merkleTreeHash(node, tmp)
		}
		index /= 2
	}
	return string(rootHash) == string(tmp)
}
