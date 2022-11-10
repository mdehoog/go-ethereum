package kzg

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/protolambda/go-kzg/bls"
	"github.com/protolambda/ztyp/codec"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

const (
	FIAT_SHAMIR_PROTOCOL_DOMAIN = "FSBLOBVERIFY_V1_"
)

// The custom types from EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#custom-types
// We deviate from the spec slightly in that we use:
//  bls.Fr for BLSFieldElement
//  bls.G1Point for G1Point
//  bls.G2Point for G2Point
type Blob []bls.Fr
type KZGCommitment [48]byte
type KZGProof [48]byte
type VersionedHash [32]byte

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

// VerifyAggregateKZGProof implements verify_aggregate_kzg_proof from the EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#verify_aggregate_kzg_proof
func VerifyAggregateKZGProof(blobs [][]bls.Fr, expectedKZGCommitments []KZGCommitment, kzgAggregatedProof KZGProof) (bool, error) {
	aggregatedPoly, aggregatedPolyCommitment, evaluationChallenge, err :=
		ComputeAggregatedPolyAndCommitment(blobs, expectedKZGCommitments)
	if err != nil {
		return false, err
	}
	y := EvaluatePolynomialInEvaluationForm(aggregatedPoly, evaluationChallenge)
	return VerifyKZGProof(aggregatedPolyCommitment, evaluationChallenge, y, kzgAggregatedProof)
}

// KZGToVersionedHash implements kzg_to_versioned_hash from EIP-4844
func KZGToVersionedHash(kzg KZGCommitment) VersionedHash {
	h := crypto.Keccak256Hash(kzg[:])
	h[0] = params.BlobCommitmentVersionKZG
	return VersionedHash([32]byte(h))
}

// PointEvaluationPrecompile implements point_evaluation_precompile from EIP-4844
func PointEvaluationPrecompile(input []byte) ([]byte, error) {
	if len(input) != 192 {
		return nil, errors.New("invalid input length")
	}

	// versioned hash: first 32 bytes
	var versionedHash [32]byte
	copy(versionedHash[:], input[:32])

	var x, y [32]byte
	// Evaluation point: next 32 bytes
	copy(x[:], input[32:64])
	// Expected output: next 32 bytes
	copy(y[:], input[64:96])

	// successfully converting x and y to bls.Fr confirms they are < MODULUS per the spec
	var xFr, yFr bls.Fr
	ok := bls.FrFrom32(&xFr, x)
	if !ok {
		return nil, errors.New("invalid evaluation point")
	}
	ok = bls.FrFrom32(&yFr, y)
	if !ok {
		return nil, errors.New("invalid expected output")
	}

	// input kzg point: next 48 bytes
	var dataKZG [48]byte
	copy(dataKZG[:], input[96:144])
	if KZGToVersionedHash(KZGCommitment(dataKZG)) != VersionedHash(versionedHash) {
		return nil, errors.New("mismatched versioned hash")
	}

	// Quotient kzg: next 48 bytes
	var quotientKZG [48]byte
	copy(quotientKZG[:], input[144:192])

	ok, err := VerifyKZGProof(KZGCommitment(dataKZG), &xFr, &yFr, KZGProof(quotientKZG))
	if err != nil {
		return nil, fmt.Errorf("verify_kzg_proof error: %v", err)
	}
	if !ok {
		return nil, errors.New("failed to verify kzg proof")
	}
	return []byte{}, nil
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

// BlobToKZGCommitment implements blob_to_kzg_commitment from the EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#blob_to_kzg_commitment
func BlobToKZGCommitment(eval Blob) KZGCommitment {
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
func ComputeAggregatedPolyAndCommitment(blobs [][]bls.Fr, commitments []KZGCommitment) ([]bls.Fr, KZGCommitment, *bls.Fr, error) {
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

	commitmentsG1 := make([]bls.G1Point, len(commitments))
	for i := 0; i < len(commitmentsG1); i++ {
		p, err := bls.FromCompressedG1(commitments[i][:])
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

// ComputeAggregateKZGProof implements compute_aggregate_kzg_proof from the EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md#compute_aggregate_kzg_proof
func ComputeAggregateKZGProof(blobs [][]bls.Fr) (KZGProof, error) {
	commitments := make([]KZGCommitment, len(blobs))
	for i, b := range blobs {
		commitments[i] = BlobToKZGCommitment(Blob(b))
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
func HashToBLSField(polys [][]bls.Fr, comms []KZGCommitment) (*bls.Fr, error) {
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
	for _, commitment := range comms {
		if err := w.Write(commitment[:]); err != nil {
			return nil, err
		}
	}
	var hash [32]byte
	copy(hash[:], sha.Sum(nil))
	return BytesToBLSField(hash), nil
}
