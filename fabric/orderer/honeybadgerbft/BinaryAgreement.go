package honeybadgerbft

import (
	"sync"

	ab "github.com/hyperledger/fabric/protos/orderer"
)

type BinaryAgreement struct {
	instanceIndex int
	total         int
	tolerance     int
	channel       chan *ab.HoneyBadgerBFTMessage
	broadcastFunc func(msg *ab.HoneyBadgerBFTMessageBinaryAgreement)
	coin          *CommonCoin

	condLock sync.Mutex
	cond     *sync.Cond

	estRecv     map[uint64]map[bool]map[int]bool
	estRecvLock sync.Mutex

	estSent     map[uint64]map[bool]bool
	estSentLock sync.Mutex

	binValues     map[uint64]map[bool]bool
	binValuesLock sync.Mutex

	auxValues     map[uint64]map[bool]map[int]bool
	auxValuesLock sync.Mutex

	exitRecv chan interface{}

	In  chan bool
	Out chan bool
}

func NewBinaryAgreement(instanceIndex int, total int, tolerance int, receiveMessageChannel chan *ab.HoneyBadgerBFTMessage, broadcastFunc func(msg ab.HoneyBadgerBFTMessage), coin *CommonCoin) (result *BinaryAgreement) {
	bc := func(msg *ab.HoneyBadgerBFTMessageBinaryAgreement) {
		broadcastFunc(ab.HoneyBadgerBFTMessage{Type: &ab.HoneyBadgerBFTMessage_BinaryAgreement{BinaryAgreement: msg}})
	}
	result = &BinaryAgreement{
		instanceIndex: instanceIndex,
		total:         total,
		tolerance:     tolerance,
		channel:       receiveMessageChannel,
		broadcastFunc: bc,
		coin:          coin,

		exitRecv: make(chan interface{}),
		In:       make(chan bool),
		Out:      make(chan bool),
	}
	result.cond = sync.NewCond(&result.condLock)
	go result.binaryAgreementService()
	return result
}

func (aba *BinaryAgreement) binaryAgreementService() {
	defer aba.coin.Stop()
	//defer logger.Debugf("ABA[%s] main service exit", aba.instanceIndex)
	defer close(aba.exitRecv)

	go aba.binaryAgreementReceiveService()

	est := <-aba.In
	logger.Debugf("ABA[%v] input: %v", aba.instanceIndex, est)
	var round uint64
	//var alreadyDecided *bool
	for {
		if !aba.inEstSentSet(round, est) {
			aba.broadcastFunc(&ab.HoneyBadgerBFTMessageBinaryAgreement{
				Round: round,
				Value: est,
				Type:  &ab.HoneyBadgerBFTMessageBinaryAgreement_Est{Est: &ab.HoneyBadgerBFTMessageBinaryAgreementEST{}},
			})
			aba.putEstSentSet(round, est)
		}

		for aba.lenBinValuesSet(round) == 0 {
			aba.condLock.Lock()
			aba.cond.Wait()
			aba.condLock.Unlock()
		}
		aba.broadcastFunc(&ab.HoneyBadgerBFTMessageBinaryAgreement{
			Round: round,
			Value: aba.listBinValuesSet(round)[0],
			Type:  &ab.HoneyBadgerBFTMessageBinaryAgreement_Aux{Aux: &ab.HoneyBadgerBFTMessageBinaryAgreementAUX{}},
		})
		var values = []bool{}
		for {
			if aba.inBinValuesSet(round, true) && aba.lenAuxValuesSet(round, true) >= aba.total-aba.tolerance {
				values = []bool{true}
				break
			}
			if aba.inBinValuesSet(round, false) && aba.lenAuxValuesSet(round, false) >= aba.total-aba.tolerance {
				values = []bool{false}
				break
			}
			var sum int
			for _, v := range aba.listBinValuesSet(round) {
				sum += aba.lenAuxValuesSet(round, v)
			}
			if sum >= aba.total-aba.tolerance {
				values = []bool{true, false}
				break
			}
			aba.condLock.Lock()
			aba.cond.Wait()
			aba.condLock.Unlock()
		}
		s := aba.coin.Get(round)
		if len(values) == 1 {
			v := values[0]
			if v == s {
				// TODO: why?
				// if alreadyDecided == nil {
				// 	alreadyDecided = &v
				// 	logger.Debugf("ABA[%v] output: %v", aba.instanceIndex, v)
				// 	aba.Out <- v
				// } else if *alreadyDecided == v {
				// 	return
				// }
				// est = v

				logger.Debugf("ABA[%v] output: %v", aba.instanceIndex, v)
				aba.Out <- v
			}
		} else {
			est = s
		}
		round++
	}
}

func (aba *BinaryAgreement) binaryAgreementReceiveService() {
	for {
		select {
		case <-aba.exitRecv:
			//logger.Debugf("ABA[%v] receive service exit", aba.instanceIndex)
			return
		case msg := <-aba.channel:
			sender := int(msg.GetSender())
			ba := msg.GetBinaryAgreement()
			round := ba.GetRound()
			value := ba.GetValue()

			switch ba.Type.(type) {
			case *ab.HoneyBadgerBFTMessageBinaryAgreement_Est:
				//logger.Infof("ABA[%v] got a EST", aba.instanceIndex)
				if aba.inEstRecvSet(round, value, sender) {
					logger.Debugf("Redundant BinaryAgreement EST Message from %v at round %v value %v", sender, round, value)
					continue
				}
				aba.putEstRecvSet(round, value, sender)
				if aba.lenEstRecvSet(round, value) >= aba.tolerance+1 && !aba.inEstSentSet(round, value) {
					aba.broadcastFunc(&ab.HoneyBadgerBFTMessageBinaryAgreement{
						Round: round,
						Value: value,
						Type:  &ab.HoneyBadgerBFTMessageBinaryAgreement_Est{Est: &ab.HoneyBadgerBFTMessageBinaryAgreementEST{}},
					})
					aba.putEstSentSet(round, value)
				}
				if aba.lenEstRecvSet(round, value) >= 2*aba.tolerance+1 {
					aba.putBinValuesSet(round, value)
					aba.cond.Signal()
				}
			case *ab.HoneyBadgerBFTMessageBinaryAgreement_Aux:
				//logger.Infof("ABA[%v] got a AUX", aba.instanceIndex)
				if aba.inAuxValuesSet(round, value, sender) {
					logger.Debugf("Redundant BinaryAgreement AUX Message from %v at round %v value %v", sender, round, value)
					continue
				}
				aba.putAuxValuesSet(round, value, sender)
				aba.cond.Signal()
			}
		}

	}
}

// helper functions

func (aba *BinaryAgreement) putEstRecvSet(round uint64, value bool, sender int) {
	aba.estRecvLock.Lock()
	defer aba.estRecvLock.Unlock()
	if aba.estRecv == nil {
		aba.estRecv = make(map[uint64]map[bool]map[int]bool)
	}
	if _, rE := aba.estRecv[round]; !rE {
		aba.estRecv[round] = make(map[bool]map[int]bool)
	}
	if _, rV := aba.estRecv[round][value]; !rV {
		aba.estRecv[round][value] = make(map[int]bool)
	}
	aba.estRecv[round][value][sender] = true
}

func (aba *BinaryAgreement) inEstRecvSet(round uint64, value bool, sender int) bool {
	aba.estRecvLock.Lock()
	defer aba.estRecvLock.Unlock()
	if aba.estRecv != nil {
		if _, rE := aba.estRecv[round]; rE {
			if _, vE := aba.estRecv[round][value]; vE {
				if _, sE := aba.estRecv[round][value][sender]; sE {
					return true //aba.estRecv[round][value][sender]
				}
			}
		}
	}
	return false
}

func (aba *BinaryAgreement) lenEstRecvSet(round uint64, value bool) int {
	aba.estRecvLock.Lock()
	defer aba.estRecvLock.Unlock()
	if aba.estRecv != nil {
		if _, rE := aba.estRecv[round]; rE {
			if _, vE := aba.estRecv[round][value]; vE {
				return len(aba.estRecv[round][value])
			}
		}
	}
	return 0
}

func (aba *BinaryAgreement) putEstSentSet(round uint64, value bool) {
	aba.estSentLock.Lock()
	defer aba.estSentLock.Unlock()
	if aba.estSent == nil {
		aba.estSent = make(map[uint64]map[bool]bool)
	}
	if _, rE := aba.estSent[round]; !rE {
		aba.estSent[round] = make(map[bool]bool)
	}
	aba.estSent[round][value] = true
}

func (aba *BinaryAgreement) inEstSentSet(round uint64, value bool) bool {
	aba.estSentLock.Lock()
	defer aba.estSentLock.Unlock()
	if aba.estSent != nil {
		if _, rE := aba.estSent[round]; rE {
			if _, rV := aba.estSent[round][value]; rV {
				return true //aba.estSent[round][value]
			}
		}
	}
	return false
}

func (aba *BinaryAgreement) putBinValuesSet(round uint64, value bool) {
	aba.binValuesLock.Lock()
	defer aba.binValuesLock.Unlock()
	if aba.binValues == nil {
		aba.binValues = make(map[uint64]map[bool]bool)
	}
	if _, rE := aba.binValues[round]; !rE {
		aba.binValues[round] = make(map[bool]bool)
	}
	aba.binValues[round][value] = true
}

func (aba *BinaryAgreement) inBinValuesSet(round uint64, value bool) bool {
	aba.binValuesLock.Lock()
	defer aba.binValuesLock.Unlock()
	if aba.binValues != nil {
		if _, rE := aba.binValues[round]; rE {
			if _, rV := aba.binValues[round][value]; rV {
				return true //aba.binValues[round][value]
			}
		}
	}
	return false
}

func (aba *BinaryAgreement) listBinValuesSet(round uint64) []bool {
	aba.binValuesLock.Lock()
	defer aba.binValuesLock.Unlock()
	result := []bool{}
	if aba.binValues != nil {
		if _, rE := aba.binValues[round]; rE {
			for v, _ := range aba.binValues[round] {
				result = append(result, v)
			}
		}
	}
	return result
}

func (aba *BinaryAgreement) lenBinValuesSet(round uint64) int {
	return len(aba.listBinValuesSet(round))
}

func (aba *BinaryAgreement) putAuxValuesSet(round uint64, value bool, sender int) {
	aba.auxValuesLock.Lock()
	defer aba.auxValuesLock.Unlock()
	if aba.auxValues == nil {
		aba.auxValues = make(map[uint64]map[bool]map[int]bool)
	}
	if _, rE := aba.auxValues[round]; !rE {
		aba.auxValues[round] = make(map[bool]map[int]bool)
	}
	if _, rV := aba.auxValues[round][value]; !rV {
		aba.auxValues[round][value] = make(map[int]bool)
	}
	aba.auxValues[round][value][sender] = true
}

func (aba *BinaryAgreement) inAuxValuesSet(round uint64, value bool, sender int) bool {
	aba.auxValuesLock.Lock()
	defer aba.auxValuesLock.Unlock()
	if aba.auxValues != nil {
		if _, rE := aba.auxValues[round]; rE {
			if _, vE := aba.auxValues[round][value]; vE {
				if _, sE := aba.auxValues[round][value][sender]; sE {
					return true // aba.auxValues[round][value][sender]
				}
			}
		}
	}
	return false
}

func (aba *BinaryAgreement) lenAuxValuesSet(round uint64, value bool) int {
	aba.auxValuesLock.Lock()
	defer aba.auxValuesLock.Unlock()
	if aba.auxValues != nil {
		if _, rE := aba.auxValues[round]; rE {
			if _, vE := aba.auxValues[round][value]; vE {
				return len(aba.auxValues[round][value])
			}
		}
	}
	return 0
}
