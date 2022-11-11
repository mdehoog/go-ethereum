package kzg

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/protolambda/go-kzg/bls"
	"github.com/protolambda/ztyp/codec"

	"github.com/ethereum/go-ethereum/params"
)

const (
	FIAT_SHAMIR_PROTOCOL_DOMAIN = "FSBLOBVERIFY_V1_"
)

type Polynomial []bls.Fr
type Polynomials [][]bls.Fr
type CommitmentSequenceImpl []KZGCommitment

func (s CommitmentSequenceImpl) At(i int) KZGCommitment {
	return s[i]
}

func (s CommitmentSequenceImpl) Len() int {
	return len(s)
}

// VerifyKZGProof implements verify_kzg_proof from the EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#verify_kzg_proof
func VerifyKZGProof(polynomialKZG KZGCommitment, z *bls.Fr, y *bls.Fr, kzgProof KZGProof) (bool, error) {
	polynomialKZGG1, err := bls.FromCompressedG1(polynomialKZG[:])
	if err != nil {
		return false, fmt.Errorf("failed to decode polynomialKZG: %v", err)
	}
	kzgProofG1, err := bls.FromCompressedG1(kzgProof[:])
	if err != nil {
		return false, fmt.Errorf("failed to decode kzgProof: %v", err)
	}
	return VerifyKZGProofFromPoints(polynomialKZGG1, z, y, kzgProofG1), nil
}

func VerifyKZGProofFromPoints(polynomialKZG *bls.G1Point, z *bls.Fr, y *bls.Fr, kzgProof *bls.G1Point) bool {
	var zG2 bls.G2Point
	bls.MulG2(&zG2, &bls.GenG2, z)
	var yG1 bls.G1Point
	bls.MulG1(&yG1, &bls.GenG1, y)

	var xMinusZ bls.G2Point
	bls.SubG2(&xMinusZ, &kzgSetupG2[1], &zG2)
	var pMinusY bls.G1Point
	bls.SubG1(&pMinusY, polynomialKZG, &yG1)

	return bls.PairingsVerify(&pMinusY, &bls.GenG2, kzgProof, &xMinusZ)
}

// VerifyAggregateKZGProof implements verify_aggregate_kzg_proof from the EIP-4844 consensus spec,
// only operating on blobs that have already been converted into polynomials.
func VerifyAggregateKZGProofFromPolynomials(blobs Polynomials, expectedKZGCommitments KZGCommitmentSequence, kzgAggregatedProof KZGProof) (bool, error) {
	aggregatedPoly, aggregatedPolyCommitment, evaluationChallenge, err :=
		ComputeAggregatedPolyAndCommitment(blobs, expectedKZGCommitments)
	if err != nil {
		return false, err
	}
	y := EvaluatePolynomialInEvaluationForm(aggregatedPoly, evaluationChallenge)
	return VerifyKZGProof(aggregatedPolyCommitment, evaluationChallenge, y, kzgAggregatedProof)
}

// ComputePowers implements compute_powers from the EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#compute_powers
func ComputePowers(r *bls.Fr, n int) []bls.Fr {
	var currentPower bls.Fr
	bls.AsFr(&currentPower, 1)
	powers := make([]bls.Fr, n)
	for i := range powers {
		powers[i] = currentPower
		bls.MulModFr(&currentPower, &currentPower, r)
	}
	return powers
}

func PolynomialToKZGCommitment(eval Polynomial) KZGCommitment {
	g1 := bls.LinCombG1(kzgSetupLagrange, []bls.Fr(eval))
	var out KZGCommitment
	copy(out[:], bls.ToCompressedG1(g1))
	return out
}

// BytesToBLSField implements bytes_to_bls_field from the EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#bytes_to_bls_field
func BytesToBLSField(h [32]byte) *bls.Fr {
	// re-interpret as little-endian
	var b [32]byte = h
	for i := 0; i < 16; i++ {
		b[31-i], b[i] = b[i], b[31-i]
	}
	zB := new(big.Int).Mod(new(big.Int).SetBytes(b[:]), BLSModulus)
	out := new(bls.Fr)
	BigToFr(out, zB)
	return out
}

// ComputeAggregatedPolyAndcommitment implements compute_aggregated_poly_and_commitment from the EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#compute_aggregated_poly_and_commitment
func ComputeAggregatedPolyAndCommitment(blobs Polynomials, commitments KZGCommitmentSequence) ([]bls.Fr, KZGCommitment, *bls.Fr, error) {
	// create challenges
	r, err := HashToBLSField(blobs, commitments)
	powers := ComputePowers(r, len(blobs))
	if len(powers) == 0 {
		return nil, KZGCommitment{}, nil, errors.New("powers can't be 0 length")
	}

	var evaluationChallenge bls.Fr
	bls.MulModFr(&evaluationChallenge, r, &powers[len(powers)-1])

	aggregatedPoly, err := bls.PolyLinComb(blobs, powers)
	if err != nil {
		return nil, KZGCommitment{}, nil, err
	}

	l := commitments.Len()
	commitmentsG1 := make([]bls.G1Point, l)
	for i := 0; i < l; i++ {
		c := commitments.At(i)
		p, err := bls.FromCompressedG1(c[:])
		if err != nil {
			return nil, KZGCommitment{}, nil, err
		}
		bls.CopyG1(&commitmentsG1[i], p)
	}
	aggregatedCommitmentG1 := bls.LinCombG1(commitmentsG1, powers)
	var aggregatedCommitment KZGCommitment
	copy(aggregatedCommitment[:], bls.ToCompressedG1(aggregatedCommitmentG1))

	return aggregatedPoly, aggregatedCommitment, &evaluationChallenge, nil
}

// ComputeAggregateKZGProofFromPolynomials implements compute_aggregate_kzg_proof from the EIP-4844
// consensus spec, only operating over blobs that are already parsed into a polynomial.
func ComputeAggregateKZGProofFromPolynomials(blobs Polynomials) (KZGProof, error) {
	commitments := make(CommitmentSequenceImpl, len(blobs))
	for i, b := range blobs {
		commitments[i] = PolynomialToKZGCommitment(Polynomial(b))
	}
	aggregatedPoly, _, evaluationChallenge, err := ComputeAggregatedPolyAndCommitment(blobs, commitments)
	if err != nil {
		return KZGProof{}, err
	}
	return ComputeKZGProof(aggregatedPoly, evaluationChallenge)
}

// ComputeAggregateKZGProof implements compute_kzg_proof from the EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#compute_kzg_proof
func ComputeKZGProof(polynomial []bls.Fr, z *bls.Fr) (KZGProof, error) {
	y := EvaluatePolynomialInEvaluationForm(polynomial, z)
	polynomialShifted := make([]bls.Fr, len(polynomial))
	for i := range polynomial {
		bls.SubModFr(&polynomialShifted[i], &polynomial[i], y)
	}
	denominatorPoly := make([]bls.Fr, len(polynomial))
	if len(polynomial) != len(Domain) {
		return KZGProof{}, errors.New("polynomial has invalid length")
	}
	for i := range polynomial {
		if bls.EqualFr(&DomainFr[i], z) {
			return KZGProof{}, errors.New("invalid z challenge")
		}
		bls.SubModFr(&denominatorPoly[i], &DomainFr[i], z)
	}
	quotientPolynomial := make([]bls.Fr, len(polynomial))
	for i := range polynomial {
		bls.DivModFr(&quotientPolynomial[i], &polynomialShifted[i], &denominatorPoly[i])
	}
	rG1 := bls.LinCombG1(kzgSetupLagrange, quotientPolynomial)
	var proof KZGProof
	copy(proof[:], bls.ToCompressedG1(rG1))
	return proof, nil
}

// EvaluatePolynomialInEvaluationForm implements evaluate_polynomial_in_evaluation_form from the EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#evaluate_polynomial_in_evaluation_form
func EvaluatePolynomialInEvaluationForm(poly []bls.Fr, x *bls.Fr) *bls.Fr {
	var result bls.Fr
	bls.EvaluatePolyInEvaluationForm(&result, poly, x, DomainFr, 0)
	return &result
}

// HashToBLSField implements hash_to_bls_field from the EIP-4844 consensus specs:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#hash_to_bls_field
func HashToBLSField(polys Polynomials, comms KZGCommitmentSequence) (*bls.Fr, error) {
	sha := sha256.New()
	w := codec.NewEncodingWriter(sha)
	if err := w.Write([]byte(FIAT_SHAMIR_PROTOCOL_DOMAIN)); err != nil {
		return nil, err
	}
	if err := w.WriteUint64(params.FieldElementsPerBlob); err != nil {
		return nil, err
	}
	if err := w.WriteUint64(uint64(len(polys))); err != nil {
		return nil, err
	}
	for _, poly := range polys {
		for _, fe := range poly {
			b32 := bls.FrTo32(&fe)
			if err := w.Write(b32[:]); err != nil {
				return nil, err
			}
		}
	}
	l := comms.Len()
	for i := 0; i < l; i++ {
		c := comms.At(i)
		if err := w.Write(c[:]); err != nil {
			return nil, err
		}
	}
	var hash [32]byte
	copy(hash[:], sha.Sum(nil))
	return BytesToBLSField(hash), nil
}
