package honeybadgerbft

import (
	"strings"

	localconfig "github.com/hyperledger/fabric/orderer/localconfig"
	"github.com/hyperledger/fabric/orderer/multichain"
	cb "github.com/hyperledger/fabric/protos/common"
	logging "github.com/op/go-logging"
)

const decodeBase = 10 //TODO: is it what i understand?

const pkgLogID = "orderer/HoneybadgerBFT"

var logger = logging.MustGetLogger(pkgLogID)

type consenterImpl struct {
	Total          int
	Tolerance      int
	ProposalSize   int
	Index          int
	ConnectionList []string
	TPKEKeys       *TPKEKeys
	TBLSKeys       *TBLSKeys
}

func (consentor *consenterImpl) HandleChain(support multichain.ConsenterSupport, metadata *cb.Metadata) (multichain.Chain, error) {
	return newChain(support, consentor), nil
}

func newChain(support multichain.ConsenterSupport, consentor *consenterImpl) *chainImpl {
	return &chainImpl{
		support:   support,
		consenter: consentor,

		sendChan: make(chan *cb.Envelope),
		exitChan: make(chan struct{}),
	}
}

func New(ordererConfig localconfig.HoneyBadgerBFT) multichain.Consenter {
	if ordererConfig.Total != len(ordererConfig.ConnectionList) || len(ordererConfig.ConnectionList) != len(ordererConfig.ThresholdEncryptionVerificationKeys) || len(ordererConfig.ThresholdEncryptionVerificationKeys) != len(ordererConfig.ThresholdSignatureVerificationKeys) {
		logger.Fatalf("Config length mismatch")
	}
	encryptionParamenter := strings.Join(ordererConfig.ThresholdEncryptionParamenter, "\n")
	encryptionGenerator := "[" + ordererConfig.ThresholdEncryptionGenerator[0] + ", " + ordererConfig.ThresholdEncryptionGenerator[1] + "]"
	encryptionPublicKey := "[" + ordererConfig.ThresholdEncryptionPublicKey[0] + ", " + ordererConfig.ThresholdEncryptionPublicKey[1] + "]"
	encryptionPrivateKey := ordererConfig.ThresholdEncryptionPrivateKey
	var encryptionVerificationKeys = make([]string, len(ordererConfig.ThresholdEncryptionVerificationKeys))
	for i, v := range ordererConfig.ThresholdEncryptionVerificationKeys {
		encryptionVerificationKeys[i] = "[" + v[0] + ", " + v[1] + "]"
	}
	signatureParamenter := strings.Join(ordererConfig.ThresholdSignatureParamenter, "\n")
	signatureGenerator := "[" + ordererConfig.ThresholdSignatureGenerator[0] + ", " + ordererConfig.ThresholdSignatureGenerator[1] + "]"
	signaturePublicKey := "[" + ordererConfig.ThresholdEncryptionPublicKey[0] + ", " + ordererConfig.ThresholdEncryptionPublicKey[1] + "]"
	signaturePrivateKey := ordererConfig.ThresholdEncryptionPrivateKey
	var signatureVerificationKeys = make([]string, len(ordererConfig.ThresholdEncryptionVerificationKeys))
	for i, v := range ordererConfig.ThresholdEncryptionVerificationKeys {
		signatureVerificationKeys[i] = "[" + v[0] + ", " + v[1] + "]"
	}
	tpkeKeys, err := NewTPKEKeys(encryptionParamenter, encryptionGenerator, encryptionPublicKey, encryptionVerificationKeys, encryptionPrivateKey)
	if err != nil {
		logger.Fatalf("Fail to construct TPKEKeys: ", err)
	}
	tblsKeys, err := NewTBLSKeys(signatureParamenter, signatureGenerator, signaturePublicKey, signatureVerificationKeys, signaturePrivateKey)
	if err != nil {
		logger.Fatalf("Fail to construct TBLSKeys: ", err)
	}
	return &consenterImpl{
		Total:          ordererConfig.Total,
		Tolerance:      ordererConfig.Tolerance,
		ProposalSize:   ordererConfig.ProposalSize,
		Index:          ordererConfig.Index,
		ConnectionList: ordererConfig.ConnectionList,
		TPKEKeys:       tpkeKeys,
		TBLSKeys:       tblsKeys,
	}
}
