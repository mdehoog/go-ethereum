package agg_kzg

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/kzg"
	"github.com/ethereum/go-ethereum/params"
	"github.com/protolambda/go-kzg/bls"
)

// Compressed BLS12-381 G1 element
type KZGCommitment [48]byte

func (p *KZGCommitment) Point() (*bls.G1Point, error) {
	return bls.FromCompressedG1(p[:])
}

// Compressed BLS12-381 G1 element
type KZGProof [48]byte

func (p *KZGProof) Point() (*bls.G1Point, error) {
	return bls.FromCompressedG1(p[:])
}

type BLSFieldElement [32]byte

func (p BLSFieldElement) MarshalText() ([]byte, error) {
	return []byte("0x" + hex.EncodeToString(p[:])), nil
}

func (p BLSFieldElement) String() string {
	return "0x" + hex.EncodeToString(p[:])
}

func (p *BLSFieldElement) UnmarshalText(text []byte) error {
	return hexutil.UnmarshalFixedText("BLSFieldElement", text, p[:])
}

// Blob data
type Blob [params.FieldElementsPerBlob]BLSFieldElement

// Parse blob into Fr elements array
func (blob *Blob) Parse() (out []bls.Fr, err error) {
	out = make([]bls.Fr, params.FieldElementsPerBlob)
	for i, chunk := range blob {
		ok := bls.FrFrom32(&out[i], chunk)
		if !ok {
			return nil, errors.New("internal error commitments")
		}
	}
	return out, nil
}

type Blobs []Blob

// Extract the crypto material underlying these blobs
func (blobs Blobs) Parse() ([][]bls.Fr, error) {
	out := make([][]bls.Fr, len(blobs))
	for i, b := range blobs {
		blob, err := b.Parse()
		if err != nil {
			return nil, fmt.Errorf("failed to parse blob %d: %v", i, err)
		}
		out[i] = blob
	}
	return out, nil
}

func computeAggregateKzgCommitment(blobs Blobs, commitments []KZGCommitment) ([]bls.Fr, *bls.G1Point, error) {
	// create challenges
	sum, err := sszHash(&BlobsAndCommitments{blobs, commitments})
	if err != nil {
		return nil, nil, err
	}
	var r bls.Fr
	hashToFr(&r, sum)

	powers := computePowers(&r, len(blobs))

	commitmentsG1 := make([]bls.G1Point, len(commitments))
	for i := 0; i < len(commitmentsG1); i++ {
		p, _ := commitments[i].Point()
		bls.CopyG1(&commitmentsG1[i], p)
	}
	aggregateCommitmentG1 := bls.LinCombG1(commitmentsG1, powers)
	var aggregateCommitment KZGCommitment
	copy(aggregateCommitment[:], bls.ToCompressedG1(aggregateCommitmentG1))

	polys, err := blobs.Parse()
	if err != nil {
		return nil, nil, err
	}
	aggregatePoly := kzg.MatrixLinComb(polys, powers)
	return aggregatePoly, aggregateCommitmentG1, nil
}

func computePowers(r *bls.Fr, n int) []bls.Fr {
	var currentPower bls.Fr
	bls.AsFr(&currentPower, 1)
	powers := make([]bls.Fr, n)
	for i := range powers {
		powers[i] = currentPower
		bls.MulModFr(&currentPower, &currentPower, r)
	}
	return powers
}

func ComputeCommitment(blob *Blob) (commitment KZGCommitment, err error) {
	frs := make([]bls.Fr, len(blob))
	for i, elem := range blob {
		if !bls.FrFrom32(&frs[i], elem) {
			return KZGCommitment{}, errors.New("blob is not canonical, error converting byte representation to a field element")
		}
	}
	// data is presented in eval form
	commitmentG1 := kzg.BlobToKzg(frs)
	var out KZGCommitment
	copy(out[:], bls.ToCompressedG1(commitmentG1))
	return out, nil
}

// Return KZG commitments that correspond to these blobs
func ComputeCommitments(blobs Blobs) (commitments []KZGCommitment, err error) {
	commitments = make([]KZGCommitment, len(blobs))

	for i, blob := range blobs {
		commitments[i], err = ComputeCommitment(&blob)
		if err != nil {
			return nil, err
		}
	}
	return commitments, nil
}

func ComputeAggregateKZGProofAndCommitments(blobs Blobs) (KZGProof, []KZGCommitment, error) {
	// Compute the commitments for each blob
	commitments, err := ComputeCommitments(blobs)
	if err != nil {
		return KZGProof{}, nil, err
	}

	// Compute the KZGProof for all of the blobs
	aggregatedProof, err := ComputeAggregateKZGProof(blobs, commitments)
	if err != nil {
		return KZGProof{}, nil, err
	}

	return aggregatedProof, commitments, nil
}

func ComputeAggregateKZGProof(blobs Blobs, commitments []KZGCommitment) (KZGProof, error) {
	// TODO: here we should return the encoding for the neutral element not 0x00.000
	var kzgProof KZGProof
	if len(blobs) == 0 {
		return KZGProof{}, nil
	}
	aggregatePoly, aggregateCommitmentG1, err := computeAggregateKzgCommitment(blobs, commitments)
	if err != nil {
		return KZGProof{}, err
	}

	var aggregateCommitment KZGCommitment
	copy(aggregateCommitment[:], bls.ToCompressedG1(aggregateCommitmentG1))

	var aggregateBlob Blob
	for i := range aggregatePoly {
		aggregateBlob[i] = bls.FrTo32(&aggregatePoly[i])
	}
	sum, err := sszHash(&PolynomialAndCommitment{aggregateBlob, aggregateCommitment})
	if err != nil {
		return KZGProof{}, err
	}
	var z bls.Fr
	hashToFr(&z, sum)

	var y bls.Fr
	kzg.EvaluatePolyInEvaluationForm(&y, aggregatePoly[:], &z)

	aggProofG1, err := kzg.ComputeProof(aggregatePoly, &z)
	if err != nil {
		return KZGProof{}, err
	}
	copy(kzgProof[:], bls.ToCompressedG1(aggProofG1))

	return kzgProof, nil
}

func VerifyAggregateKZGProof(blobs Blobs, blobKzgs []KZGCommitment, aggregatedProof KZGProof) error {
	aggregatePoly, aggregateCommitmentG1, err := computeAggregateKzgCommitment(blobs, blobKzgs)
	if err != nil {
		return fmt.Errorf("failed to compute aggregate commitment: %v", err)
	}
	var aggregateBlob Blob
	for i := range aggregatePoly {
		aggregateBlob[i] = bls.FrTo32(&aggregatePoly[i])
	}
	var aggregateCommitment KZGCommitment
	copy(aggregateCommitment[:], bls.ToCompressedG1(aggregateCommitmentG1))
	sum, err := sszHash(&PolynomialAndCommitment{aggregateBlob, aggregateCommitment})
	if err != nil {
		return err
	}
	var z bls.Fr
	hashToFr(&z, sum)

	var y bls.Fr
	kzg.EvaluatePolyInEvaluationForm(&y, aggregatePoly[:], &z)

	aggregateProofG1, err := aggregatedProof.Point()
	if err != nil {
		return fmt.Errorf("aggregate proof parse error: %v", err)
	}
	if !kzg.VerifyKzgProof(aggregateCommitmentG1, &z, &y, aggregateProofG1) {
		return errors.New("failed to verify kzg")
	}
	return nil

}
