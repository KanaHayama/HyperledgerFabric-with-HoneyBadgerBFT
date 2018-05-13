package honeybadgerbft

import (
	"github.com/Nik-U/pbc"
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
	MaxMalicious   int
	ProposalSize   int
	Index          int
	ConnectionList []string
	TPKEKeys       TPKEKeys
	TBLSKeys       TBLSKeys
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
	encryptionPublicKey, ok := TPKEPairing.NewG1().SetString("["+ordererConfig.ThresholdEncryptionPublicKey[0]+", "+ordererConfig.ThresholdEncryptionPublicKey[1]+"]", decodeBase) //TODO: Or G2?
	if !ok {
		logger.Fatalf("Decode threshold encryption public key failed: %v", ordererConfig.ThresholdEncryptionPublicKey)
	}
	encryptionPrivateKey, ok := TPKEPairing.NewZr().SetString(ordererConfig.ThresholdEncryptionPrivateKey, decodeBase)
	if !ok {
		logger.Fatalf("Decode threshold encryption private key failed: %s", ordererConfig.ThresholdEncryptionPrivateKey)
	}
	var encryptionVerificationKeys []*pbc.Element
	for _, v := range ordererConfig.ThresholdEncryptionVerificationKeys {
		verificationKey, ok := TPKEPairing.NewG1().SetString("["+v[0]+", "+v[1]+"]", decodeBase)
		if !ok {
			logger.Fatalf("Decode threshold encryption verification key failed: %v", v)
		}
		encryptionVerificationKeys = append(encryptionVerificationKeys, verificationKey)
	}

	signaturePublicKey, ok := TBLSPairing.NewG1().SetString("["+ordererConfig.ThresholdEncryptionPublicKey[0]+", "+ordererConfig.ThresholdEncryptionPublicKey[1]+"]", decodeBase) //TODO: Or G2?
	if !ok {
		logger.Fatalf("Decode threshold signature public key failed: %v", ordererConfig.ThresholdEncryptionPublicKey)
	}
	signaturePrivateKey, ok := TBLSPairing.NewZr().SetString(ordererConfig.ThresholdEncryptionPrivateKey, decodeBase)
	if !ok {
		logger.Fatalf("Decode threshold signature private key failed: %s", ordererConfig.ThresholdEncryptionPrivateKey)
	}
	var signatureVerificationKeys []*pbc.Element
	for _, v := range ordererConfig.ThresholdEncryptionVerificationKeys {
		verificationKey, ok := TBLSPairing.NewG1().SetString("["+v[0]+", "+v[1]+"]", decodeBase)
		if !ok {
			logger.Fatalf("Decode threshold signature verification key failed: %v", v)
		}
		signatureVerificationKeys = append(signatureVerificationKeys, verificationKey)
	}
	tpkeKeys, err := NewTPKEKeys(encryptionPublicKey, encryptionVerificationKeys, encryptionPrivateKey)
	if err != nil {
		logger.Fatalf("Fail to construct TPKEKeys: ", err)
	}
	tblsKeys, err := NewTBLSKeys(signaturePublicKey, signatureVerificationKeys, signaturePrivateKey)
	if err != nil {
		logger.Fatalf("Fail to construct TBLSKeys: ", err)
	}
	return &consenterImpl{
		Total:          ordererConfig.Total,
		MaxMalicious:   ordererConfig.MaxMalicious,
		ProposalSize:   ordererConfig.ProposalSize,
		Index:          ordererConfig.Index,
		ConnectionList: ordererConfig.ConnectionList,
		TPKEKeys:       tpkeKeys,
		TBLSKeys:       tblsKeys,
	}
}
