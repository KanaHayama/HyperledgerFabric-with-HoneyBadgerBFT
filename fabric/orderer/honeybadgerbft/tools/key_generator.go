package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/Nik-U/pbc"
)

const DecodeBase = 10

func main() {

	h := flag.Bool("h", false, "usage")
	out := flag.String("o", "keys.txt", "output file name")
	param := flag.String("p", "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1", "paramenter")
	gen := flag.String("g", "[4264083391895955901265257040028479149400169025615345260303986214726423231173928285256791041998919055277112394516001733341992693480052725918957267301183325, 2116426609166886503385333553365957364401816544109920990955286798122869276384003469957105697651246200288946800075692216092350705727159751274607530017817646]", "generator")
	n := flag.Int("n", 4, "number of nodes")
	t := flag.Int("t", 1, "number of tolerance")
	flag.Parse()
	if *h {
		flag.Usage()
	} else {
		p, err := pbc.NewParamsFromString(*param)
		if err != nil {
			fmt.Println(err)
		}
		pairing := p.NewPairing()
		generator, ok := pairing.NewG1().SetString(*gen, DecodeBase)
		if !ok {
			fmt.Println("Decode generator failed: %s", *gen)
		}
		// Random polynomial coeffici
		secret := pairing.NewZr().Rand()
		a := []*pbc.Element{secret}
		k := *n - 2*(*t)
		for i := 1; i < k; i++ {
			a = append(a, pairing.NewZr().Rand())
		}
		// Polynomial evaluation
		function := func(x int32) *pbc.Element {
			y := pairing.NewZr().Set0()
			xx := pairing.NewZr().Set1()
			for _, coeff := range a {
				y = pairing.NewZr().Mul(coeff, xx).ThenAdd(y)
				xx = xx.ThenMulInt32(x)
			}
			return y
		}
		// Shares of master secret key
		SKs := make([]*pbc.Element, *n)
		for i := 1; i < *n+1; i++ {
			SKs[i-1] = function(int32(i))
		}
		// Verification keys
		VK := pairing.NewG1().PowZn(generator, secret)
		VKs := make([]*pbc.Element, len(SKs))
		for i, xx := range SKs {
			VKs[i] = pairing.NewG2().PowZn(generator, xx)
		}
		// Check reconstruction of 0
		// TODO:
		// Write file
		file, err := os.Create(*out)
		if err != nil {
			fmt.Println(err)
		}
		defer file.Close()
		w := bufio.NewWriter(file)
		w.WriteString("n:" + strconv.Itoa(*n) + "\n")
		w.WriteString("t:" + strconv.Itoa(*t) + "\n")
		w.WriteString("paramenter:\n" + *param + "\n")
		w.WriteString("generator:\n" + *gen + "\n")
		w.WriteString("public key:\n" + VK.String() + "\n")
		w.WriteString("verification keys:\n")
		for _, k := range VKs {
			w.WriteString(k.String() + "\n")
		}
		w.WriteString("private keys:\n")
		for _, k := range SKs {
			w.WriteString(k.String() + "\n")
		}
		w.Flush()
	}
}
