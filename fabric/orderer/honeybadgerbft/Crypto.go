package honeybadgerbft

import (
	"crypto/sha256"
	"fmt"

	"github.com/Nik-U/pbc"
)

// TODO: make sure NewG1 or NewG2

const DecodeBase = 10

type TPKEKeys struct {
	pairing   *pbc.Pairing
	generator *pbc.Element

	publicKey        *pbc.Element
	verificationKeys []*pbc.Element
	privateKey       *pbc.Element
}

func NewTPKEKeys(paramenter string, generator string, publicKey string, verificationKeys []string, privateKey string) (*TPKEKeys, error) {
	param, err := pbc.NewParamsFromString(paramenter)
	if err != nil {
		return nil, err
	}
	pairing := param.NewPairing()
	gen, ok := pairing.NewG1().SetString(generator, DecodeBase)
	if !ok {
		return nil, fmt.Errorf("Decode generator failed: %s", generator)
	}
	pub, ok := pairing.NewG1().SetString(publicKey, DecodeBase) //TODO: Or G2?
	if !ok {
		return nil, fmt.Errorf("Decode public key failed: %s", publicKey)
	}
	if len(verificationKeys) == 0 {
		return nil, fmt.Errorf("[]VerificationKeys is nil")
	}
	var veri = make([]*pbc.Element, len(verificationKeys))
	for i, s := range verificationKeys {
		veri[i], ok = pairing.NewG1().SetString(s, DecodeBase)
		if !ok {
			return nil, fmt.Errorf("Decode verification key %v failed: %s", i, s)
		}
	}
	pri, ok := pairing.NewZr().SetString(privateKey, DecodeBase)
	if !ok {
		return nil, fmt.Errorf("Decode private key failed: %s", privateKey)
	}
	return &TPKEKeys{
		pairing:   pairing,
		generator: gen,

		publicKey:        pub,
		verificationKeys: veri,
		privateKey:       pri,
	}, nil
}

func (k *TPKEKeys) xor(x []byte, y []byte) ([]byte, error) {
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("Incorrect []byte length")
	}
	result := make([]byte, 32)
	for i := range result {
		result[i] = x[i] ^ y[i]
	}
	return result, nil
}

func (k *TPKEKeys) hashG(e *pbc.Element) []byte {
	s := sha256.New()
	s.Write(e.Bytes())
	return s.Sum(nil)
}

func (k *TPKEKeys) hashH(g *pbc.Element, x []byte) *pbc.Element {
	s := sha256.New()
	s.Write(g.Bytes())
	s.Write(x)
	return k.pairing.NewG2().SetFromHash(s.Sum(nil))
}

func (k *TPKEKeys) NewG1AndSetBytes(b []byte) *pbc.Element {
	return k.pairing.NewG1().SetBytes(b)
}

func (k *TPKEKeys) NewG2AndSetBytes(b []byte) *pbc.Element {
	return k.pairing.NewG2().SetBytes(b)
}

func (k *TPKEKeys) Encrypt(data []byte) (*pbc.Element, []byte, *pbc.Element, error) {
	if len(data) != 32 {
		return nil, nil, nil, fmt.Errorf("Incorrect []byte length")
	}
	r := k.pairing.NewZr().Rand()
	U := k.pairing.NewG1().PowZn(k.generator, r)
	V, err := k.xor(data, k.hashG(k.pairing.NewG1().PowZn(k.publicKey, r)))
	if err != nil {
		return nil, nil, nil, err
	}
	mid := k.hashH(U, V)
	W := k.pairing.NewG2().PowZn(mid, r)
	return U, V, W, nil
}

func (k *TPKEKeys) VerifyCiphertext(U *pbc.Element, V []byte, W *pbc.Element) bool {
	H := k.hashH(U, V)
	p1 := k.pairing.NewGT().Pair(k.generator, W)
	p2 := k.pairing.NewGT().Pair(U, H)
	return p1.Equals(p2)
}

func (k *TPKEKeys) DecryptShare(U *pbc.Element, V []byte, W *pbc.Element) (*pbc.Element, error) {
	if !k.VerifyCiphertext(U, V, W) {
		return nil, fmt.Errorf("Verify ciphertext failed")
	}
	return k.pairing.NewG1().PowZn(U, k.privateKey), nil
}

func (k *TPKEKeys) lagrange(set []int, i int) *pbc.Element {
	reduce := func(list []int) *pbc.Element {
		r := k.pairing.NewZr().Set1()
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

func (k *TPKEKeys) CombineShares(shares map[int]*pbc.Element, U *pbc.Element, V []byte, W *pbc.Element) ([]byte, error) {
	reduce := func(list []*pbc.Element) *pbc.Element {
		r := k.pairing.NewG1().Set1()
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
		l = append(l, k.pairing.NewG1().PowZn(share, k.lagrange(set, i)))
	}
	return k.xor(k.hashG(reduce(l)), V)
}

////////////////////////////////////////////////////////////////////

type TBLSKeys struct {
	pairing   *pbc.Pairing
	generator *pbc.Element

	publicKey        *pbc.Element
	verificationKeys []*pbc.Element
	privateKey       *pbc.Element
}

func NewTBLSKeys(paramenter string, generator string, publicKey string, verificationKeys []string, privateKey string) (*TBLSKeys, error) {
	param, err := pbc.NewParamsFromString(paramenter)
	if err != nil {
		return nil, err
	}
	pairing := param.NewPairing()
	gen, ok := pairing.NewG1().SetString(generator, DecodeBase)
	if !ok {
		return nil, fmt.Errorf("Decode generator failed: %s", generator)
	}
	pub, ok := pairing.NewG1().SetString(publicKey, DecodeBase) //TODO: Or G2?
	if !ok {
		return nil, fmt.Errorf("Decode public key failed: %s", publicKey)
	}
	if len(verificationKeys) == 0 {
		return nil, fmt.Errorf("[]VerificationKeys is nil")
	}
	var veri = make([]*pbc.Element, len(verificationKeys))
	for i, s := range verificationKeys {
		veri[i], ok = pairing.NewG1().SetString(s, DecodeBase)
		if !ok {
			return nil, fmt.Errorf("Decode verification key %v failed: %s", i, s)
		}
	}
	pri, ok := pairing.NewZr().SetString(privateKey, DecodeBase)
	if !ok {
		return nil, fmt.Errorf("Decode private key failed: %s", privateKey)
	}
	return &TBLSKeys{
		pairing:   pairing,
		generator: gen,

		publicKey:        pub,
		verificationKeys: veri,
		privateKey:       pri,
	}, nil
}

func (k *TBLSKeys) NewG1AndSetBytes(b []byte) *pbc.Element {
	return k.pairing.NewG1().SetBytes(b)
}

func (k *TBLSKeys) HashMessage(message []byte) *pbc.Element {
	s := sha256.New()
	s.Write(message)
	h := s.Sum(nil)
	return k.pairing.NewG1().SetFromHash(h)
}

func (k *TBLSKeys) Sign(hash *pbc.Element) *pbc.Element {
	return k.pairing.NewG1().PowZn(hash, k.privateKey)
}

func (k *TBLSKeys) VerifyShare(signature *pbc.Element, hash *pbc.Element, index int) bool {
	p1 := k.pairing.NewGT().Pair(signature, k.generator)
	p2 := k.pairing.NewGT().Pair(hash, k.verificationKeys[index])
	r := p1.Equals(p2)
	return r
}

func (k *TBLSKeys) lagrange(set []int, i int) *pbc.Element {
	reduce := func(list []int) *pbc.Element {
		r := k.pairing.NewZr().Set1()
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

func (k *TBLSKeys) CombineShares(signatures map[int]*pbc.Element) *pbc.Element {
	reduce := func(list []*pbc.Element) *pbc.Element {
		r := k.pairing.NewG1().Set1()
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
		l = append(l, k.pairing.NewG1().PowZn(sig, k.lagrange(set, i)))
	}
	return reduce(l)
}

func (k *TBLSKeys) VerifySignature(signature *pbc.Element, hash *pbc.Element) bool {
	p1 := k.pairing.NewGT().Pair(signature, k.generator)
	p2 := k.pairing.NewGT().Pair(hash, k.publicKey)
	return p1.Equals(p2)
}
