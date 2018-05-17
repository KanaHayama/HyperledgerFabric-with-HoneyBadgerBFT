package honeybadgerbft

type CommonSubset struct {
	ordererIndex int
	total        int
	tolerance    int
	rbc          []*ReliableBroadcast
	aba          []*BinaryAgreement

	In  chan []byte
	Out chan [][]byte
}

func NewCommonSubset(ordererIndex int, total int, tolerance int, rbc []*ReliableBroadcast, aba []*BinaryAgreement) (result *CommonSubset) {
	result = &CommonSubset{
		ordererIndex: ordererIndex,
		total:        total,
		tolerance:    tolerance,
		rbc:          rbc,
		aba:          aba,

		In:  make(chan []byte),
		Out: make(chan [][]byte),
	}
	go result.commonSubsetService()
	return result
}

func (acs *CommonSubset) commonSubsetService() {
	data := <-acs.In
	logger.Debugf("ACS input: []byte(len=%v) --> RBC[%v]", len(data), acs.ordererIndex)
	acs.rbc[acs.ordererIndex].In <- data

	var abaInputted = make(map[int]bool)

	var joinRBC = make([]chan interface{}, acs.total)
	var killRBC = make([]chan interface{}, acs.total)
	var rbcOutputs = make([][]byte, acs.total)
	receiveRBC := func(instanceIndex int) {
		select {
		case <-killRBC[instanceIndex]:
			return
		case data := <-acs.rbc[instanceIndex].Out:
			rbcOutputs[instanceIndex] = data
			if !abaInputted[instanceIndex] {
				acs.aba[instanceIndex].In <- true
				abaInputted[instanceIndex] = true
			}
			joinRBC[instanceIndex] <- nil
		}
	}
	for index := range acs.rbc {
		joinRBC[index] = make(chan interface{})
		killRBC[index] = make(chan interface{})
	}
	for index := range acs.rbc {
		joinRBC[index] = make(chan interface{})
		go receiveRBC(index)
	}

	var joinABA = make(chan interface{})
	var abaOutputs = make([]bool, acs.total)
	receiveABA := func(instanceIndex int) {
		data := <-acs.aba[instanceIndex].Out
		abaOutputs[instanceIndex] = data
		sum := 0
		for _, v := range abaOutputs {
			if v {
				sum++
			}
		}
		if sum >= acs.total-acs.tolerance {
			for index, aba := range acs.aba {
				if !abaInputted[index] {
					aba.In <- false
					abaInputted[index] = true
				}
			}
		}
		joinABA <- nil
	}
	for index := range acs.aba {
		go receiveABA(index)
	}
	for range acs.aba {
		<-joinABA
	}

	for index, abaOutput := range abaOutputs {
		if abaOutput {
			<-joinRBC[index]
			if rbcOutputs[index] == nil {
				logger.Panicf("RBC output of %v instance is nil", index)
			}
		} else {
			killRBC[index] <- nil
			rbcOutputs[index] = nil
		}
	}

	var avaliableCount int
	for _, v := range rbcOutputs {
		if v != nil {
			avaliableCount++
		}
	}
	logger.Debugf("ACS output: [][]byte(len=%v,aval=%v)", len(rbcOutputs), avaliableCount)
	acs.Out <- rbcOutputs
}
