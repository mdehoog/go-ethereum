package kzg

import (
	"encoding/json"
	"errors"
	"math/big"
	"math/bits"

	"github.com/ethereum/go-ethereum/params"

	"github.com/protolambda/go-kzg/bls"
)

// KZG CRS for G2
var kzgSetupG2 []bls.G2Point

// KZG CRS for commitment computation
var kzgSetupLagrange []bls.G1Point

// KZG CRS for G1 (only used in tests (for proof creation))
var KzgSetupG1 []bls.G1Point

type JSONTrustedSetup struct {
	SetupG1       []bls.G1Point
	SetupG2       []bls.G2Point
	SetupLagrange []bls.G1Point
}

// Initialize KZG subsystem (load the trusted setup data)
func init() {
	var parsedSetup = JSONTrustedSetup{}

	// TODO: This is dirty. KZG setup should be loaded using an actual config file directive
	err := json.Unmarshal([]byte(KZGSetupStr), &parsedSetup)
	if err != nil {
		panic(err)
	}

	kzgSetupG2 = parsedSetup.SetupG2
	kzgSetupLagrange = bitReversalPermutation(parsedSetup.SetupLagrange)
	KzgSetupG1 = parsedSetup.SetupG1

	initDomain()
}

// Bit-reversal permutation helper functions

// Check if `value` is a power of two integer.
func isPowerOfTwo(value uint64) bool {
	return value > 0 && (value&(value-1) == 0)
}

// Reverse `order` bits of integer n
func reverseBits(n, order uint64) uint64 {
	if !isPowerOfTwo(order) {
		panic("Order must be a power of two.")
	}

	return bits.Reverse64(n) >> (65 - bits.Len64(order))
}

// Return a copy of the input array permuted by bit-reversing the indexes.
func bitReversalPermutation(l []bls.G1Point) []bls.G1Point {
	out := make([]bls.G1Point, len(l))

	order := uint64(len(l))

	for i := range l {
		out[i] = l[reverseBits(uint64(i), order)]
	}

	return out
}

// Compute KZG proof at point `z` with `polynomial` being in evaluation form.
// compute_kzg_proof from the EIP-4844 spec.
func ComputeProof(eval []bls.Fr, z *bls.Fr) (*bls.G1Point, error) {
	if len(eval) != params.FieldElementsPerBlob {
		return nil, errors.New("invalid eval polynomial for proof")
	}

	// To avoid overflow/underflow, convert elements into int
	var poly [params.FieldElementsPerBlob]big.Int
	for i := range poly {
		frToBig(&poly[i], &eval[i])
	}
	var zB big.Int
	frToBig(&zB, z)

	// Shift our polynomial first (in evaluation form we can't handle the division remainder)
	var yB big.Int
	var y bls.Fr
	EvaluatePolyInEvaluationForm(&y, eval, z)
	frToBig(&yB, &y)
	var polyShifted [params.FieldElementsPerBlob]big.Int

	for i := range polyShifted {
		polyShifted[i].Mod(new(big.Int).Sub(&poly[i], &yB), BLSModulus)
	}

	var denomPoly [params.FieldElementsPerBlob]big.Int
	for i := range denomPoly {
		// Make sure we won't induce a division by zero later. Shouldn't happen if using Fiat-Shamir challenges
		if Domain[i].Cmp(&zB) == 0 {
			return nil, errors.New("inavlid z challenge")
		}
		denomPoly[i].Mod(new(big.Int).Sub(Domain[i], &zB), BLSModulus)
	}

	// Calculate quotient polynomial by doing point-by-point division
	var quotientPoly [params.FieldElementsPerBlob]bls.Fr
	for i := range quotientPoly {
		var tmp big.Int
		blsDiv(&tmp, &polyShifted[i], &denomPoly[i])
		_ = BigToFr(&quotientPoly[i], &tmp)
	}
	return bls.LinCombG1(kzgSetupLagrange, quotientPoly[:]), nil
}
