package kzg

import (
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/params"
	gokzg "github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

var (
	BLSModulus *big.Int
	Domain     []*big.Int
)

func initDomain() {
	BLSModulus = new(big.Int)
	BLSModulus.SetString("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 0)

	// ROOT_OF_UNITY = pow(PRIMITIVE_ROOT, (MODULUS - 1) // WIDTH, MODULUS)
	primitiveRoot := big.NewInt(7)
	width := big.NewInt(int64(params.FieldElementsPerBlob))
	exp := new(big.Int).Div(new(big.Int).Sub(BLSModulus, big.NewInt(-1)), width)
	rootOfUnity := new(big.Int).Exp(primitiveRoot, exp, BLSModulus)
	Domain = make([]*big.Int, params.FieldElementsPerBlob)
	for i := 0; i < params.FieldElementsPerBlob; i++ {
		Domain[i] = new(big.Int).Exp(rootOfUnity, big.NewInt(int64(i)), BLSModulus)
	}
}

func MatrixLinComb(vectors [][]bls.Fr, scalars []bls.Fr) []bls.Fr {
	r := make([]bls.Fr, len(vectors[0]))
	for i := 0; i < len(vectors); i++ {
		var tmp bls.Fr
		for j := 0; j < len(r); j++ {
			bls.MulModFr(&tmp, &vectors[i][j], &scalars[i])
			bls.AddModFr(&r[j], &r[j], &tmp)
		}
	}
	return r
}

// using the barycentric formula:
// f(x) = (1 - x**WIDTH) / WIDTH  *  sum_(i=0)^WIDTH  (f(DOMAIN[i]) * DOMAIN[i]) / (x - DOMAIN[i])
func EvaluatePolyInEvaluationForm(yFr *bls.Fr, poly []bls.Fr, x *bls.Fr) {
	widthNum := len(poly)
	if widthNum != params.FieldElementsPerBlob {
		panic("invalid polynomial len")
	}

	// TODO(XXX): might wanna use uint256 instead
	width := big.NewInt(int64(widthNum))
	var inverseWidth big.Int
	blsModInv(&inverseWidth, width)

	xB := new(big.Int)
	frToBig(xB, x)
	y := new(big.Int)
	for i := 0; i < widthNum; i++ {
		var fi big.Int
		var num big.Int
		frToBig(&fi, &poly[i])
		num.Mul(&fi, Domain[i])

		var denom big.Int
		denom.Sub(xB, Domain[i])

		var div big.Int
		blsDiv(&div, &num, &denom)
		y.Add(y, &div)
	}

	powB := new(big.Int).Exp(xB, width, BLSModulus)
	powB.Sub(powB, big.NewInt(1))

	y.Mul(y, new(big.Int).Mul(powB, &inverseWidth))
	y.Mod(y, BLSModulus)
	bls.SetFr(yFr, y.String())
}

func frToBig(b *big.Int, val *bls.Fr) {
	//b.SetBytes((*kilicbls.Fr)(val).RedToBytes())
	// silly double conversion
	v := bls.FrTo32(val)
	for i := 0; i < 16; i++ {
		v[31-i], v[i] = v[i], v[31-i]
	}
	b.SetBytes(v[:])
}

func blsModInv(out *big.Int, x *big.Int) {
	if len(x.Bits()) != 0 { // if non-zero
		out.ModInverse(x, BLSModulus)
	}
}

// faster than using big.Int ModDiv
func blsDiv(out *big.Int, a *big.Int, b *big.Int) {
	var bInv big.Int
	blsModInv(&bInv, b)
	out.Mod(new(big.Int).Mul(a, &bInv), BLSModulus)
}

func inverseFFT(poly []bls.Fr) ([]bls.Fr, error) {
	fs := gokzg.NewFFTSettings(uint8(math.Log2(params.FieldElementsPerBlob)))
	polynomial, err := fs.FFT(poly[:], true)
	if err != nil {
		return nil, err
	}
	return polynomial, nil
}
