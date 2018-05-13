package honeybadgerbft

import (
	"crypto/sha256"
	"fmt"

	"github.com/Nik-U/pbc"
)

const (
	//TODO: Find a better way to load params dynamiclly
	TPKEParamString = `type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1`
)

var (
	TPKEPairing   *pbc.Pairing
	TPKEGenerator *pbc.Element
)

func init() {
	param, _ := pbc.NewParamsFromString(TPKEParamString)
	TPKEPairing = param.NewPairing()
	TPKEGenerator, _ = TPKEPairing.NewG1().SetString("[4264083391895955901265257040028479149400169025615345260303986214726423231173928285256791041998919055277112394516001733341992693480052725918957267301183325,2116426609166886503385333553365957364401816544109920990955286798122869276384003469957105697651246200288946800075692216092350705727159751274607530017817646]", 10) //g1 == g2 //TODO: use my own generator one day
}

type TPKEKeys struct {
	publicKey        *pbc.Element
	verificationKeys []*pbc.Element
	privateKey       *pbc.Element
}

func NewTPKEKeys(publicKey *pbc.Element, verificationKeys []*pbc.Element, privateKey *pbc.Element) (TPKEKeys, error) {
	if publicKey == nil {
		return TPKEKeys{}, fmt.Errorf("PublicKey is nil")
	}
	if privateKey == nil {
		return TPKEKeys{}, fmt.Errorf("Privatekey is nil")
	}
	return TPKEKeys{
		publicKey:        publicKey,
		verificationKeys: verificationKeys,
		privateKey:       privateKey,
	}, nil
}

func (k TPKEKeys) xor(x []byte, y []byte) []byte {
	if len(x) != 32 || len(y) != 32 {
		logger.Panicf("Incorrect []byte length")
	}
	result := make([]byte, 32)
	for i := range result {
		result[i] = x[i] ^ y[i]
	}
	return result
}

func (k TPKEKeys) hashG(e *pbc.Element) []byte {
	s := sha256.New()
	s.Write(e.Bytes())
	return s.Sum(nil)
}

func (k TPKEKeys) hashH(g *pbc.Element, x []byte) *pbc.Element {
	s := sha256.New()
	s.Write(g.Bytes())
	s.Write(x)
	return TPKEPairing.NewG2().SetFromHash(s.Sum(nil))
}

func (k TPKEKeys) Encrypt(data []byte) (*pbc.Element, []byte, *pbc.Element) {
	if len(data) != 32 {
		logger.Panicf("Incorrect []byte length")
	}
	r := TPKEPairing.NewZr().Rand()
	U := TPKEPairing.NewG1().PowZn(TPKEGenerator, r)
	V := k.xor(data, k.hashG(TPKEPairing.NewG1().PowZn(k.publicKey, r)))
	mid := k.hashH(U, V)
	W := TPKEPairing.NewG2().PowZn(mid, r)
	return U, V, W
}

func (k TPKEKeys) VerifyCiphertext(U *pbc.Element, V []byte, W *pbc.Element) bool {
	H := k.hashH(U, V)
	p1 := TPKEPairing.NewGT().Pair(TPKEGenerator, W)
	p2 := TPKEPairing.NewGT().Pair(U, H)
	return p1.Equals(p2)
}

func (k TPKEKeys) DecryptShare(U *pbc.Element, V []byte, W *pbc.Element) *pbc.Element {
	if !k.VerifyCiphertext(U, V, W) {
		logger.Panicf("Verify ciphertext failed")
	}
	return TPKEPairing.NewG1().PowZn(U, k.privateKey)
}

func (k TPKEKeys) lagrange(set []int, i int) *pbc.Element {
	reduce := func(list []int) *pbc.Element {
		r := TPKEPairing.NewZr().Set1()
		for _, v := range list {
			r.ThenMulInt32(int32(v))
		}
		return r
	}
	var num []int
	var den []int
	for _, j := range set {
		if i != j {
			num = append(num, 0-j-1)
			den = append(den, i-j)
		}
	}
	return reduce(num).ThenDiv(reduce(den))
}

func (k TPKEKeys) CombineShares(shares map[int]*pbc.Element, U *pbc.Element, V []byte, W *pbc.Element) []byte {
	reduce := func(list []*pbc.Element) *pbc.Element {
		r := TPKEPairing.NewG1().Set1()
		for _, v := range list {
			r.ThenMul(v)
		}
		return r
	}
	var set []int
	for i := range shares {
		set = append(set, i)
	}
	var l []*pbc.Element
	for i, share := range shares {
		l = append(l, TPKEPairing.NewG1().PowZn(share, k.lagrange(set, i)))
	}
	return k.xor(k.hashG(reduce(l)), V)
}

////////////////////////////////////////////////////////////////////

const (
	//Use same params with TPKE for convenience
	TBLSParamString = TPKEParamString
)

var (
	TBLSPairing   *pbc.Pairing
	TBLSGenerator *pbc.Element
)

func init() {
	param, _ := pbc.NewParamsFromString(TBLSParamString)
	TBLSPairing = param.NewPairing()
	TBLSGenerator, _ = TBLSPairing.NewG1().SetString("[4264083391895955901265257040028479149400169025615345260303986214726423231173928285256791041998919055277112394516001733341992693480052725918957267301183325,2116426609166886503385333553365957364401816544109920990955286798122869276384003469957105697651246200288946800075692216092350705727159751274607530017817646]", 10) //TODO: use my own generator one day
}

type TBLSKeys struct {
	//Same as TPKEPublicKey for convenience
	publicKey        *pbc.Element
	verificationKeys []*pbc.Element
	privateKey       *pbc.Element
}

func NewTBLSKeys(publicKey *pbc.Element, verificationKeys []*pbc.Element, privateKey *pbc.Element) (TBLSKeys, error) {
	if publicKey == nil {
		return TBLSKeys{}, fmt.Errorf("PublicKey is nil")
	}
	if privateKey == nil {
		return TBLSKeys{}, fmt.Errorf("Privatekey is nil")
	}
	return TBLSKeys{
		publicKey:        publicKey,
		verificationKeys: verificationKeys,
		privateKey:       privateKey,
	}, nil
}

func (k TBLSKeys) HashMessage(message []byte) *pbc.Element {
	s := sha256.New()
	s.Write(message)
	h := s.Sum(nil)
	return TBLSPairing.NewG1().SetFromHash(h)
}

func (k TBLSKeys) Sign(hash *pbc.Element) *pbc.Element {
	return TBLSPairing.NewG1().PowZn(hash, k.privateKey)
}

func (k TBLSKeys) VerifyShare(signature *pbc.Element, hash *pbc.Element, index int) bool {
	p1 := TBLSPairing.NewGT().Pair(signature, TBLSGenerator)
	p2 := TBLSPairing.NewGT().Pair(hash, k.verificationKeys[index])
	r := p1.Equals(p2)
	return r
}

func (k TBLSKeys) lagrange(set []int, i int) *pbc.Element {
	reduce := func(list []int) *pbc.Element {
		r := TBLSPairing.NewZr().Set1()
		for _, v := range list {
			r.ThenMulInt32(int32(v))
		}
		return r
	}
	var num []int
	var den []int
	for _, j := range set {
		if i != j {
			num = append(num, 0-j-1)
			den = append(den, i-j)
		}
	}
	return reduce(num).ThenDiv(reduce(den))
}

func (k TBLSKeys) CombineShares(signatures map[int]*pbc.Element) *pbc.Element {
	reduce := func(list []*pbc.Element) *pbc.Element {
		r := TBLSPairing.NewG1().Set1()
		for _, v := range list {
			r.ThenMul(v)
		}
		return r
	}
	var set []int
	for i := range signatures {
		set = append(set, i)
	}
	var l []*pbc.Element
	for i, sig := range signatures {
		l = append(l, TBLSPairing.NewG1().PowZn(sig, k.lagrange(set, i)))
	}
	return reduce(l)
}

func (k TBLSKeys) VerifySignature(signature *pbc.Element, hash *pbc.Element) bool {
	p1 := TBLSPairing.NewGT().Pair(signature, TBLSGenerator)
	p2 := TBLSPairing.NewGT().Pair(hash, k.publicKey)
	return p1.Equals(p2)
}

////////////////////////////////////////////////////////////////////

func main() {
	fmt.Println("Distributed key generator NOT ready")
}
