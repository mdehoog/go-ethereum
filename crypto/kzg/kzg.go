package kzg

import (
	"encoding/json"
	"math/bits"

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
