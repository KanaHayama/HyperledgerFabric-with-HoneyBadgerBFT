package honeybadgerbft

import (
	"math/rand"
	"sync"
	"time"

	"github.com/hyperledger/fabric/orderer/multichain"
	cb "github.com/hyperledger/fabric/protos/common"
	ab "github.com/hyperledger/fabric/protos/orderer"
)

type chainImpl struct {
	support         multichain.ConsenterSupport
	consenter       *consenterImpl
	messageChannels MessageChannels

	sendChan chan *cb.Envelope
	exitChan chan struct{}
}

func (ch *chainImpl) Start() {
	messageChannels, err := Register(ch.support.ChainID(), ch.consenter.ConnectionList, ch.consenter.Index)
	if err != nil {
		logger.Panicf("Can not start chain: %s", err)
	}
	ch.messageChannels = messageChannels
	go ch.main()
}

func (ch *chainImpl) Halt() {
	select {
	case <-ch.exitChan:
		// Allow multiple halts without panic
	default:
		close(ch.exitChan)
	}
}

// Enqueue accepts a message and returns true on acceptance, or false on shutdown
func (ch *chainImpl) Enqueue(env *cb.Envelope) bool {
	select {
	case ch.sendChan <- env:
		return true
	case <-ch.exitChan:
		return false
	}
}

// Errored only closes on exit
func (ch *chainImpl) Errored() <-chan struct{} {
	return ch.exitChan
}

func (ch *chainImpl) main() {
	///////////////////////////////
	//filter out NEW_HEIGHT nessage
	///////////////////////////////
	var fallthoughChannel = make(chan *ab.HoneyBadgerBFTMessage)
	var newHeight = make(chan uint64, 666666)
	filterNewHeightMessageService := func() {
		for {
			msg := <-ch.messageChannels.Receive
			switch msg.Type.(type) {
			case *ab.HoneyBadgerBFTMessage_New_Height:
				newHeight <- msg.GetHeight()
			default:
				fallthoughChannel <- msg
			}
		}
	}
	go filterNewHeightMessageService()

	////////////////////////////////
	//dispatch message by height
	///////////////////////////////
	var heightMap = make(map[uint64]chan *ab.HoneyBadgerBFTMessage) //TODO: use unlimited queues instead
	var heightMapLock sync.Mutex
	getByHeight := func(height uint64) chan *ab.HoneyBadgerBFTMessage {
		heightMapLock.Lock()
		defer heightMapLock.Unlock()
		result, exist := heightMap[height]
		if !exist {
			result = make(chan *ab.HoneyBadgerBFTMessage, 666666)
			heightMap[height] = result
		}
		return result
	}
	dispatchMessageByHeightService := func() {
		for {
			msg := <-fallthoughChannel
			getByHeight(msg.GetHeight()) <- msg
		}
	}
	go dispatchMessageByHeightService()

	////////////////////////////////////
	//main loop
	///////////////////////////////////
	var proceed = make(chan uint64, 666666) // Must buffered
	var nonCommittedBatch []*cb.Envelope
	for {
		///////////////////////
		//preperations
		///////////////////////
		workingHeight := ch.support.Height() + 1
		sendFunc := func(index int, msg ab.HoneyBadgerBFTMessage) {
			msg.Height = workingHeight
			msg.Receiver = uint64(index)
			ch.messageChannels.Send <- msg
		}
		broadcastFunc := func(msg ab.HoneyBadgerBFTMessage) {
			for i := 0; i < ch.consenter.Total; i++ {
				sendFunc(i, msg)
			}
		}

		////////////////////////////
		//handle messages
		////////////////////////////

		//proceed <- workingHeight //FOR TEST

		select {
		case <-ch.exitChan:
			logger.Debug("Exiting")
			return

		case height := <-proceed:
			if height != workingHeight {
				logger.Debugf("Redudant proceed signal(current=%v, request=%v)", workingHeight, height)
				continue
			}
			startTime := time.Now()
			logger.Debugf("Generating block at height %v", workingHeight)
			broadcastFunc(ab.HoneyBadgerBFTMessage{Type: &ab.HoneyBadgerBFTMessage_New_Height{New_Height: &ab.HoneyBadgerBFTMessageNewHeight{}}})
			var exitHeight = make(chan interface{})

			/////////////////////////////////////////////////////////
			//dispatch message by servise type
			////////////////////////////////////////////////////////
			var coinRecvMsgChannel = make(chan *ab.HoneyBadgerBFTMessage)
			var abaRecvMsgChannel = make(chan *ab.HoneyBadgerBFTMessage)
			var rbcRecvMsgChannel = make(chan *ab.HoneyBadgerBFTMessage)
			var tkpeRecvMsgChannel = make(chan *ab.HoneyBadgerBFTMessage)
			dispatchByTypeService := func() {
				for {
					select {
					case <-exitHeight:
						return
					case msg := <-getByHeight(workingHeight):
						switch msg.Type.(type) {
						case *ab.HoneyBadgerBFTMessage_CommonCoin:
							coinRecvMsgChannel <- msg
						case *ab.HoneyBadgerBFTMessage_BinaryAgreement:
							abaRecvMsgChannel <- msg
						case *ab.HoneyBadgerBFTMessage_ReliableBroadcast:
							rbcRecvMsgChannel <- msg
						case *ab.HoneyBadgerBFTMessage_ThresholdEncryption:
							tkpeRecvMsgChannel <- msg
						}
					}
				}
			}
			go dispatchByTypeService()

			/////////////////////////////////////////
			//dispatch by components
			/////////////////////////////////////////
			var coinInstanceRecvMsgChannels = make([]chan *ab.HoneyBadgerBFTMessage, ch.consenter.Total)
			var abaInstanceRecvMsgChannels = make([]chan *ab.HoneyBadgerBFTMessage, ch.consenter.Total)
			var rbcInstanceRecvMsgChannels = make([]chan *ab.HoneyBadgerBFTMessage, ch.consenter.Total)
			for i := 0; i < ch.consenter.Total; i++ {
				coinInstanceRecvMsgChannels[i] = make(chan *ab.HoneyBadgerBFTMessage, 666666)
				abaInstanceRecvMsgChannels[i] = make(chan *ab.HoneyBadgerBFTMessage, 666666)
				rbcInstanceRecvMsgChannels[i] = make(chan *ab.HoneyBadgerBFTMessage, 666666)
			}
			dispatchByInstance := func() {
				for {
					select {
					case <-exitHeight:
						return
					case msg := <-coinRecvMsgChannel:
						coinInstanceRecvMsgChannels[int(msg.GetInstance())] <- msg
					case msg := <-abaRecvMsgChannel:
						abaInstanceRecvMsgChannels[int(msg.GetInstance())] <- msg
					case msg := <-rbcRecvMsgChannel:
						rbcInstanceRecvMsgChannels[msg.GetInstance()] <- msg
					}
				}
			}
			go dispatchByInstance()

			////////////////////////////////////////
			//setup COIN ABA RBC components
			////////////////////////////////////////
			var coin = make([]*CommonCoin, ch.consenter.Total)
			var aba = make([]*BinaryAgreement, ch.consenter.Total)
			var rbc = make([]*ReliableBroadcast, ch.consenter.Total)
			for i := 0; i < ch.consenter.Total; i++ {
				instanceIndex := i // NOTE important to copy i
				componentSendFunc := func(index int, msg ab.HoneyBadgerBFTMessage) {
					msg.Instance = uint64(instanceIndex)
					sendFunc(index, msg)
				}
				componentBroadcastFunc := func(msg ab.HoneyBadgerBFTMessage) {
					msg.Instance = uint64(instanceIndex)
					broadcastFunc(msg)
				}
				rbc[i] = NewReliableBroadcast(i, ch.consenter.Total, ch.consenter.MaxMalicious, ch.consenter.Index, i, rbcInstanceRecvMsgChannels[i], componentSendFunc, componentBroadcastFunc) // TODO: a better way to eval whether i is leader, ListenAddress may difference with address in connectionlist
				coin[i] = NewCommonCoin(i, ch.consenter.MaxMalicious, coinInstanceRecvMsgChannels[i], componentBroadcastFunc, ch.consenter.TBLSKeys)
				aba[i] = NewBinaryAgreement(i, ch.consenter.Total, ch.consenter.MaxMalicious, abaInstanceRecvMsgChannels[i], componentBroadcastFunc, coin[i]) // May stop automatically?				                                                                                                                                                                    //TODO
			}
			///////////////////////////////////////
			//setup ACS component (using N instances of COIN ABA RBC)
			///////////////////////////////////////
			acs := NewCommonSubset(ch.consenter.Index, ch.consenter.Total, ch.consenter.MaxMalicious, rbc, aba)

			////////////////////////////////////////////////
			//setup HoneyBadgerBFT component (using ACS)
			////////////////////////////////////////////////
			block := NewHoneyBadgerBlock(ch.consenter.Total, ch.consenter.MaxMalicious, tkpeRecvMsgChannel, broadcastFunc, ch.consenter.TPKEKeys, acs)

			///////////////////////////////////////
			//propose transactions
			//////////////////////////////////////
			randomSelectFunc := func(batch []*cb.Envelope, number int) (result []*cb.Envelope) {
				result = batch[:]
				if len(batch) <= number {
					return result
				}
				for len(result) > number {
					i := rand.Intn(len(batch))
					result = append(result[:i], result[i+1:]...)
				}
				return result
			}
			proposalBatch := nonCommittedBatch[:]
			if uint32(len(proposalBatch)) > ch.support.SharedConfig().BatchSize().MaxMessageCount {
				proposalBatch = nonCommittedBatch[:ch.support.SharedConfig().BatchSize().MaxMessageCount]
			}
			proposalBatch = randomSelectFunc(proposalBatch, ch.consenter.ProposalSize)

			////////////////////////////////////////////
			//generate blocks
			///////////////////////////////////////////
			block.In <- proposalBatch
			committedBatch := <-block.Out
			if len(committedBatch) == 0 {
				logger.Warningf("No transaction committed!")
			} else {
				for _, tx := range committedBatch {
					batches, committers, _, _ := ch.support.BlockCutter().Ordered(tx)
					for i, batch := range batches {
						block := ch.support.CreateNextBlock(batch)
						ch.support.WriteBlock(block, committers[i], nil)
					}
					for i, v := range nonCommittedBatch {
						if v.String() == tx.String() {
							//delete tx
							nonCommittedBatch = append(nonCommittedBatch[:i], nonCommittedBatch[i+1:]...)
						}
					}
				}
				batch, committers := ch.support.BlockCutter().Cut() //cut imidiatelly to prevent timer (if use) competition among orderers
				if len(batch) > 0 {
					block := ch.support.CreateNextBlock(batch)
					ch.support.WriteBlock(block, committers, nil)
				}
			}
			///////////////////////////////////////////
			//clean up
			///////////////////////////////////////////
			close(exitHeight)
			// TODO: delete heightMap that <= working height. NOTE: synchronize problem

			logger.Infof("Generate %v block(s) in %s", ch.support.Height()-workingHeight+1, time.Since(startTime).String())

		case tx := <-ch.sendChan:
			nonCommittedBatch = append(nonCommittedBatch, tx)
			logger.Debugf("A new tx enqueued, len(nonCommittedBatch) = %v, wait the length reach %v", len(nonCommittedBatch), ch.support.SharedConfig().BatchSize().MaxMessageCount)
			if uint32(len(nonCommittedBatch)) >= ch.support.SharedConfig().BatchSize().MaxMessageCount {
				proceed <- workingHeight
				logger.Debugf("Non-committed batch have collected enough transactons")
			}
		case otherHeight := <-newHeight:
			if otherHeight == workingHeight {
				proceed <- workingHeight
				logger.Debugf("Notified to generate new blocks")
			} else if otherHeight > workingHeight {
				//TODO: broadcast require block messages
			}
		}
	}
}
