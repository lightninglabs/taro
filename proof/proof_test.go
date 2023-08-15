package proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

var (
	// proofFileHexFileName is the name of the file that contains the hex
	// proof file data. The proof file contains all proofs from the
	// testdata/proof_tlv_encoding_other.json test vector file.
	proofFileHexFileName = filepath.Join(testDataFileName, "proof-file.hex")

	// proofHexFileName is the name of the file that contains the hex proof
	// data. The proof is generated from the proof "valid regtest split
	// proof" in the proof_tlv_encoding_other.json test vector file.
	proofHexFileName = filepath.Join(testDataFileName, "proof.hex")

	// ownershipProofHexFileName is the name of the file that contains the
	// hex proof data. The proof is a random test proof from an integration
	// test run.
	ownershipProofHexFileName = filepath.Join(
		testDataFileName, "ownership-proof.hex",
	)

	otherTestVectorName     = "proof_tlv_encoding_other.json"
	generatedTestVectorName = "proof_tlv_encoding_generated.json"

	allTestVectorFiles = []string{
		generatedTestVectorName,
		otherTestVectorName,
		"proof_tlv_encoding_error_cases.json",
	}
)

func assertEqualCommitmentProof(t *testing.T, expected, actual *CommitmentProof) {
	require.Equal(t, expected.Proof.AssetProof, actual.Proof.AssetProof)
	require.Equal(
		t, expected.Proof.TaprootAssetProof,
		actual.Proof.TaprootAssetProof,
	)
	require.Equal(t, expected.TapSiblingPreimage, actual.TapSiblingPreimage)
}

func assertEqualTaprootProof(t *testing.T, expected, actual *TaprootProof) {
	t.Helper()
	require.Equal(t, expected.OutputIndex, actual.OutputIndex)
	require.Equal(t, expected.InternalKey, actual.InternalKey)
	if expected.CommitmentProof == nil {
		require.Nil(t, actual.CommitmentProof)
	} else {
		assertEqualCommitmentProof(
			t, expected.CommitmentProof, actual.CommitmentProof,
		)
	}
	if expected.TapscriptProof == nil {
		require.Nil(t, actual.TapscriptProof)
	} else {
		require.Equal(t, expected.TapscriptProof, actual.TapscriptProof)
	}
}

func assertEqualProof(t *testing.T, expected, actual *Proof) {
	t.Helper()

	require.Equal(t, expected.PrevOut, actual.PrevOut)
	require.Equal(t, expected.BlockHeader, actual.BlockHeader)
	require.Equal(t, expected.BlockHeight, actual.BlockHeight)
	require.Equal(t, expected.AnchorTx, actual.AnchorTx)
	require.Equal(t, expected.TxMerkleProof, actual.TxMerkleProof)
	require.Equal(t, expected.Asset, actual.Asset)

	assertEqualTaprootProof(t, &expected.InclusionProof, &actual.InclusionProof)

	for i := range expected.ExclusionProofs {
		assertEqualTaprootProof(
			t, &expected.ExclusionProofs[i], &actual.ExclusionProofs[i],
		)
	}

	require.Equal(t, expected.ExclusionProofs, actual.ExclusionProofs)

	if expected.SplitRootProof != nil {
		assertEqualTaprootProof(
			t, expected.SplitRootProof, actual.SplitRootProof,
		)
	} else {
		require.Nil(t, actual.SplitRootProof)
	}

	require.Equal(t, expected.MetaReveal, actual.MetaReveal)

	for i := range expected.AdditionalInputs {
		require.Equal(
			t, expected.AdditionalInputs[i].Version,
			actual.AdditionalInputs[i].Version,
		)
		require.Len(
			t, actual.AdditionalInputs,
			len(expected.AdditionalInputs),
		)
		for j := range expected.AdditionalInputs[i].proofs {
			e, err := expected.AdditionalInputs[i].ProofAt(uint32(j))
			require.NoError(t, err)

			a, err := actual.AdditionalInputs[i].ProofAt(uint32(j))
			require.NoError(t, err)
			assertEqualProof(t, e, a)
		}
	}

	require.Equal(t, expected.ChallengeWitness, actual.ChallengeWitness)
}

func TestProofEncoding(t *testing.T) {
	t.Parallel()

	testBlocks := readTestData(t)
	oddTxBlock := testBlocks[0]

	txMerkleProof, err := NewTxMerkleProof(oddTxBlock.Transactions, 0)
	require.NoError(t, err)

	genesis := asset.RandGenesis(t, asset.Collectible)
	groupKey := asset.RandGroupKey(t, genesis)
	groupReveal := asset.GroupKeyReveal{
		RawKey:        asset.ToSerialized(&groupKey.GroupPubKey),
		TapscriptRoot: test.RandBytes(32),
	}

	mintCommitment, assets, err := commitment.Mint(
		genesis, groupKey, &commitment.AssetDetails{
			Type:             asset.Collectible,
			ScriptKey:        test.PubToKeyDesc(test.RandPubKey(t)),
			Amount:           nil,
			LockTime:         1337,
			RelativeLockTime: 6,
		},
	)
	require.NoError(t, err)
	asset := assets[0]
	asset.GroupKey.RawKey = keychain.KeyDescriptor{}

	// Empty the raw script key, since we only serialize the tweaked
	// pubkey. We'll also force the main script key to be an x-only key as
	// well.
	asset.ScriptKey.PubKey, err = schnorr.ParsePubKey(
		schnorr.SerializePubKey(asset.ScriptKey.PubKey),
	)
	require.NoError(t, err)

	asset.ScriptKey.TweakedScriptKey = nil

	_, commitmentProof, err := mintCommitment.Proof(
		asset.TapCommitmentKey(), asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	leaf1 := txscript.NewBaseTapLeaf([]byte{1})
	leaf2 := txscript.NewBaseTapLeaf([]byte{2})
	testLeafPreimage := commitment.NewPreimageFromLeaf(leaf1)
	testLeafPreimage2 := commitment.NewPreimageFromLeaf(leaf2)
	testBranchPreimage := commitment.NewPreimageFromBranch(
		txscript.NewTapBranch(leaf1, leaf2),
	)
	proof := Proof{
		PrevOut:       genesis.FirstPrevOut,
		BlockHeader:   oddTxBlock.Header,
		BlockHeight:   42,
		AnchorTx:      *oddTxBlock.Transactions[0],
		TxMerkleProof: *txMerkleProof,
		Asset:         *asset,
		InclusionProof: TaprootProof{
			OutputIndex: 1,
			InternalKey: test.RandPubKey(t),
			CommitmentProof: &CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: testLeafPreimage,
			},
			TapscriptProof: nil,
		},
		ExclusionProofs: []TaprootProof{
			{
				OutputIndex: 2,
				InternalKey: test.RandPubKey(t),
				CommitmentProof: &CommitmentProof{
					Proof:              *commitmentProof,
					TapSiblingPreimage: testLeafPreimage,
				},
				TapscriptProof: nil,
			},
			{
				OutputIndex:     3,
				InternalKey:     test.RandPubKey(t),
				CommitmentProof: nil,
				TapscriptProof: &TapscriptProof{
					TapPreimage1: testBranchPreimage,
					TapPreimage2: testLeafPreimage2,
					Bip86:        true,
				},
			},
			{
				OutputIndex:     4,
				InternalKey:     test.RandPubKey(t),
				CommitmentProof: nil,
				TapscriptProof: &TapscriptProof{
					Bip86: true,
				},
			},
		},
		SplitRootProof: &TaprootProof{
			OutputIndex: 4,
			InternalKey: test.RandPubKey(t),
			CommitmentProof: &CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: nil,
			},
		},
		MetaReveal: &MetaReveal{
			Data: []byte("quoth the raven nevermore"),
			Type: MetaOpaque,
		},
		AdditionalInputs: []File{},
		ChallengeWitness: wire.TxWitness{[]byte("foo"), []byte("bar")},
		GenesisReveal:    &genesis,
		GroupKeyReveal:   &groupReveal,
	}
	file, err := NewFile(V0, proof, proof)
	require.NoError(t, err)
	proof.AdditionalInputs = []File{*file, *file}

	var buf bytes.Buffer
	require.NoError(t, proof.Encode(&buf))
	var decodedProof Proof
	require.NoError(t, decodedProof.Decode(&buf))

	assertEqualProof(t, &proof, &decodedProof)

	// Test with a nil tapscript root in the group reveal.
	proof.GroupKeyReveal.TapscriptRoot = nil
	file, err = NewFile(V0, proof, proof)
	require.NoError(t, err)
	proof.AdditionalInputs = []File{*file, *file}

	buf.Reset()
	require.NoError(t, proof.Encode(&buf))
	var decodedProof2 Proof
	require.NoError(t, decodedProof2.Decode(&buf))

	assertEqualProof(t, &proof, &decodedProof2)

	// Ensure that operations on a proof of unknown version fail.
	unknownFile, err := NewFile(Version(212), proof, proof)
	require.NoError(t, err)

	firstProof, err := unknownFile.ProofAt(0)
	require.Nil(t, firstProof)
	require.ErrorIs(t, err, ErrUnknownVersion)

	firstProofBytes, err := unknownFile.RawProofAt(0)
	require.Nil(t, firstProofBytes)
	require.ErrorIs(t, err, ErrUnknownVersion)

	lastProof, err := unknownFile.LastProof()
	require.Nil(t, lastProof)
	require.ErrorIs(t, err, ErrUnknownVersion)

	lastProofBytes, err := unknownFile.RawLastProof()
	require.Nil(t, lastProofBytes)
	require.ErrorIs(t, err, ErrUnknownVersion)

	err = unknownFile.AppendProof(proof)
	require.ErrorIs(t, err, ErrUnknownVersion)

	err = unknownFile.ReplaceLastProof(proof)
	require.ErrorIs(t, err, ErrUnknownVersion)
}

func genRandomGenesisWithProof(t testing.TB, assetType asset.Type,
	amt *uint64, tapscriptPreimage *commitment.TapscriptPreimage,
	noMetaHash bool, metaReveal *MetaReveal,
	genesisMutator genMutator) (Proof, *btcec.PrivateKey) {

	t.Helper()

	genesisPrivKey := test.RandPrivKey(t)

	// If we have a specified meta reveal, then we'll replace the meta hash
	// with the hash of the reveal instead.
	assetGenesis := asset.RandGenesis(t, assetType)
	if metaReveal != nil {
		assetGenesis.MetaHash = metaReveal.MetaHash()
	} else if noMetaHash {
		assetGenesis.MetaHash = [32]byte{}
	}

	if genesisMutator != nil {
		genesisMutator(&assetGenesis)
	}

	assetGroupKey := asset.RandGroupKey(t, assetGenesis)
	tapCommitment, assets, err := commitment.Mint(
		assetGenesis, assetGroupKey, &commitment.AssetDetails{
			Type: assetType,
			ScriptKey: test.PubToKeyDesc(
				genesisPrivKey.PubKey(),
			),
			Amount:           amt,
			LockTime:         0,
			RelativeLockTime: 0,
		},
	)
	require.NoError(t, err)
	genesisAsset := assets[0]
	_, commitmentProof, err := tapCommitment.Proof(
		genesisAsset.TapCommitmentKey(),
		genesisAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	var tapscriptSibling *chainhash.Hash
	if tapscriptPreimage != nil {
		tapscriptSibling, err = tapscriptPreimage.TapHash()
		require.NoError(t, err)
	}

	internalKey := test.SchnorrPubKey(t, genesisPrivKey)
	tapscriptRoot := tapCommitment.TapscriptRoot(tapscriptSibling)
	taprootKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot[:],
	)
	taprootScript := test.ComputeTaprootScript(t, taprootKey)
	genesisTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{
			PkScript: taprootScript,
			Value:    330,
		}},
	}
	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(genesisTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]

	// We'll use the genesis hash of the mainnet chain as the parent block.
	blockHeader := wire.NewBlockHeader(
		0, chaincfg.MainNetParams.GenesisHash, merkleRoot, 0, 0,
	)
	blockHeader.Timestamp = time.Unix(test.RandInt[int64](), 0)

	// We'll set the block height to 1, as the genesis block is at height 0.
	blockHeight := uint32(1)

	txMerkleProof, err := NewTxMerkleProof([]*wire.MsgTx{genesisTx}, 0)
	require.NoError(t, err)

	return Proof{
		PrevOut:       genesisTx.TxIn[0].PreviousOutPoint,
		BlockHeader:   *blockHeader,
		BlockHeight:   blockHeight,
		AnchorTx:      *genesisTx,
		TxMerkleProof: *txMerkleProof,
		Asset:         *genesisAsset,
		InclusionProof: TaprootProof{
			OutputIndex: 0,
			InternalKey: internalKey,
			CommitmentProof: &CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: tapscriptPreimage,
			},
			TapscriptProof: nil,
		},
		MetaReveal:       metaReveal,
		ExclusionProofs:  nil,
		AdditionalInputs: nil,
	}, genesisPrivKey
}

type genMutator func(*asset.Genesis)

func TestGenesisProofVerification(t *testing.T) {
	t.Parallel()

	// Create a script tree that we'll use for our tapscript sibling test
	// cases.
	scriptInternalKey := test.RandPrivKey(t).PubKey()
	leaf1 := test.ScriptHashLock(t, []byte("foobar"))
	leaf2 := test.ScriptSchnorrSig(t, scriptInternalKey)

	// The order doesn't matter here as they are sorted before hashing.
	branch := txscript.NewTapBranch(leaf1, leaf2)
	amount := uint64(5000)

	testCases := []struct {
		name              string
		assetType         asset.Type
		amount            *uint64
		tapscriptPreimage *commitment.TapscriptPreimage
		metaReveal        *MetaReveal
		noMetaHash        bool
		genesisMutator    genMutator
		expectedErr       error
	}{
		{
			name:       "collectible genesis",
			assetType:  asset.Collectible,
			noMetaHash: true,
		},
		{
			name:      "collectible with leaf preimage",
			assetType: asset.Collectible,
			tapscriptPreimage: commitment.NewPreimageFromLeaf(
				leaf1,
			),
			noMetaHash: true,
		},
		{
			name:      "collectible with branch preimage",
			assetType: asset.Collectible,
			tapscriptPreimage: commitment.NewPreimageFromBranch(
				branch,
			),
			noMetaHash: true,
		},
		{
			name:       "normal genesis",
			assetType:  asset.Normal,
			amount:     &amount,
			noMetaHash: true,
		},
		{
			name:      "normal with leaf preimage",
			assetType: asset.Normal,
			amount:    &amount,
			tapscriptPreimage: commitment.NewPreimageFromLeaf(
				leaf1,
			),
			noMetaHash: true,
		},
		{
			name:      "normal with branch preimage",
			assetType: asset.Normal,
			amount:    &amount,
			tapscriptPreimage: commitment.NewPreimageFromBranch(
				branch,
			),
			noMetaHash: true,
		},
		{
			name:      "normal asset with a meta reveal",
			assetType: asset.Normal,
			amount:    &amount,
			metaReveal: &MetaReveal{
				Data: []byte("meant in croking nevermore"),
			},
		},
		{
			name:      "collectible with a meta reveal",
			assetType: asset.Collectible,
			metaReveal: &MetaReveal{
				Data: []byte("shall be lifted nevermore"),
			},
		},
		{
			name:      "collectible invalid meta reveal",
			assetType: asset.Collectible,
			metaReveal: &MetaReveal{
				Data: []byte("shall be lifted nevermore"),
			},
			genesisMutator: func(genesis *asset.Genesis) {
				// Modify the genesis to make the meta reveal
				// invalid.
				genesis.MetaHash[0] ^= 1
			},
			expectedErr: ErrMetaRevealMismatch,
		},
		{
			name:        "normal asset has meta hash no meta reveal",
			assetType:   asset.Normal,
			amount:      &amount,
			expectedErr: ErrMetaRevealRequired,
		},
		{
			name: "collectible asset has meta hash no " +
				"meta reveal",
			assetType:   asset.Collectible,
			expectedErr: ErrMetaRevealRequired,
		},
	}

	testVectors := &TestVectors{}
	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(tt *testing.T) {
			genesisProof, _ := genRandomGenesisWithProof(
				tt, tc.assetType, tc.amount,
				tc.tapscriptPreimage, tc.noMetaHash,
				tc.metaReveal, tc.genesisMutator,
			)
			_, err := genesisProof.Verify(
				context.Background(), nil, MockHeaderVerifier,
			)
			require.ErrorIs(t, err, tc.expectedErr)

			var buf bytes.Buffer
			err = genesisProof.Encode(&buf)
			require.NoError(tt, err)

			if tc.expectedErr == nil {
				testVectors.ValidTestCases = append(
					testVectors.ValidTestCases,
					&ValidTestCase{
						Proof: NewTestFromProof(
							t, &genesisProof,
						),
						Expected: hex.EncodeToString(
							buf.Bytes(),
						),
						Comment: tc.name,
					},
				)
			}
		})
	}

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, generatedTestVectorName, testVectors)
}

// TestUpdateManualProofs is only executed when updating test vectors and is
// responsible for updating the following files:
//   - testdata/proof_tlv_encoding_other.json
//   - testdata/proof.hex
//   - testdata/proof-file.hex
func TestUpdateManualProofs(t *testing.T) {
	if !test.GeneratingTestVectors {
		t.Skip("Not generating test vectors, skipping proof file " +
			"updates")
	}

	// First, we update the proof_tlv_encoding_other.json file. This file
	// contains actual proofs from a random integration test run. We know
	// that the proof's content is valid, but in case the encoding of it
	// changes, we just re-encode it here and update the file.
	var (
		otherVectors = &TestVectors{}
		fileProofs   []Proof
	)

	test.ParseTestVectors(t, otherTestVectorName, &otherVectors)
	for idx := range otherVectors.ValidTestCases {
		proof := otherVectors.ValidTestCases[idx].Proof.ToProof(t)

		// We need to update the inclusion proofs in case anything in
		// the asset serialization changed.
		assetTree, err := commitment.NewAssetCommitment(&proof.Asset)
		require.NoError(t, err)
		assetTapTree, err := commitment.NewTapCommitment(assetTree)
		require.NoError(t, err)
		_, commitmentProof, err := assetTapTree.Proof(
			proof.Asset.TapCommitmentKey(),
			proof.Asset.AssetCommitmentKey(),
		)
		require.NoError(t, err)
		proof.InclusionProof.CommitmentProof.Proof = *commitmentProof

		var buf bytes.Buffer
		require.NoError(t, proof.Encode(&buf))

		expectedStr := hex.EncodeToString(buf.Bytes())
		otherVectors.ValidTestCases[idx].Expected = expectedStr

		comment := otherVectors.ValidTestCases[idx].Comment
		switch {
		// The proof with the comment "valid regtest split proof" is
		// also the proof we encode in the proof.hex file.
		case comment == "valid regtest split proof":
			err := os.WriteFile(
				proofHexFileName, []byte(expectedStr), 0644,
			)
			require.NoError(t, err)

		// The proof with the comment "valid regtest ownership proof" is
		// also the proof we encode in the ownership-proof.hex file.
		case comment == "valid regtest ownership proof":
			err := os.WriteFile(
				ownershipProofHexFileName, []byte(expectedStr),
				0644,
			)
			require.NoError(t, err)

		// Any proof that starts with the comment "valid regtest proof
		// file index X", we add to the proof-file.hex file.
		case strings.Contains(comment, "valid regtest proof file index"):
			fileProofs = append(fileProofs, *proof)

		default:
			// Ignore any other test proofs, we don't use those in
			// a different context, only as test vectors.
		}
	}
	test.WriteTestVectors(t, otherTestVectorName, otherVectors)

	// And finally, we update the proof-file.hex file to contain all the
	// proofs from the testdata/proof_tlv_encoding_other.json file that have
	// a comment starting with "valid regtest proof file".
	file, err := NewFile(V0, fileProofs...)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = file.Encode(&buf)
	require.NoError(t, err)

	err = os.WriteFile(
		proofFileHexFileName, []byte(hex.EncodeToString(buf.Bytes())),
		0644,
	)
	require.NoError(t, err)
}

// TestProofBlockHeaderVerification ensures that an error returned by the
// HeaderVerifier callback is correctly propagated by the Verify proof method.
func TestProofBlockHeaderVerification(t *testing.T) {
	t.Parallel()

	proof, _ := genRandomGenesisWithProof(
		t, asset.Collectible, nil, nil, true, nil, nil,
	)

	// Create a base reference for the block header and block height. We
	// will later modify these proof fields.
	var (
		originalBlockHeader = proof.BlockHeader
		originalBlockHeight = proof.BlockHeight
	)

	// Header verifier compares given header to expected header. Verifier
	// does not return error.
	errHeaderVerifier := fmt.Errorf("invalid block header")
	headerVerifier := func(header wire.BlockHeader, height uint32) error {
		// Compare given block header against base reference block
		// header.
		if header != originalBlockHeader || height != originalBlockHeight {
			return errHeaderVerifier
		}
		return nil
	}

	// Verify that the original proof block header is as expected and
	// therefore an error is not returned.
	_, err := proof.Verify(
		context.Background(), nil, headerVerifier,
	)
	require.NoError(t, err)

	// Modify proof block header, then check that the verification function
	// propagates the correct error.
	proof.BlockHeader.Nonce += 1
	_, actualErr := proof.Verify(
		context.Background(), nil, headerVerifier,
	)
	require.ErrorIs(t, actualErr, errHeaderVerifier)

	// Reset proof block header.
	proof.BlockHeader.Nonce = originalBlockHeader.Nonce

	// Modify proof block height, then check that the verification function
	// propagates the correct error.
	proof.BlockHeight += 1
	_, actualErr = proof.Verify(
		context.Background(), nil, headerVerifier,
	)
	require.ErrorIs(t, actualErr, errHeaderVerifier)
}

// TestProofFileVerification ensures that the proof file encoding and decoding
// works as expected.
func TestProofFileVerification(t *testing.T) {
	proofHex, err := os.ReadFile(proofFileHexFileName)
	require.NoError(t, err)

	proofBytes, err := hex.DecodeString(
		strings.Trim(string(proofHex), "\n"),
	)
	require.NoError(t, err)

	f := &File{}
	err = f.Decode(bytes.NewReader(proofBytes))
	require.NoError(t, err)

	_, err = f.Verify(context.Background(), MockHeaderVerifier)
	require.NoError(t, err)

	// Ensure that verification of a proof of unknown version fails.
	f.Version = Version(212)

	lastAsset, err := f.Verify(context.Background(), MockHeaderVerifier)
	require.Nil(t, lastAsset)
	require.ErrorIs(t, err, ErrUnknownVersion)
}

// TestProofVerification ensures that the proof encoding and decoding works as
// expected.
func TestProofVerification(t *testing.T) {
	proofHex, err := os.ReadFile(proofHexFileName)
	require.NoError(t, err)

	proofBytes, err := hex.DecodeString(
		strings.Trim(string(proofHex), "\n"),
	)
	require.NoError(t, err)

	p := &Proof{}
	err = p.Decode(bytes.NewReader(proofBytes))
	require.NoError(t, err)

	assetID := p.Asset.ID()
	t.Logf("Proof asset ID: %x", assetID[:])

	inclusionTxOut := p.AnchorTx.TxOut[p.InclusionProof.OutputIndex]
	t.Logf("Proof inclusion tx out: %x", inclusionTxOut.PkScript)
	proofKey, proofTree, err := p.InclusionProof.DeriveByAssetInclusion(
		&p.Asset,
	)
	require.NoError(t, err)
	rootHash := proofTree.TapscriptRoot(nil)
	t.Logf("Proof internal key: %x",
		p.InclusionProof.InternalKey.SerializeCompressed())
	t.Logf("Proof root hash: %x", rootHash[:])
	t.Logf("Proof key: %x", proofKey.SerializeCompressed())

	var buf bytes.Buffer
	require.NoError(t, p.Asset.Encode(&buf))
	t.Logf("Proof asset encoded: %x", buf.Bytes())
}

// TestOwnershipProofVerification ensures that the ownership proof encoding and
// decoding as well as the verification works as expected.
func TestOwnershipProofVerification(t *testing.T) {
	proofHex, err := os.ReadFile(ownershipProofHexFileName)
	require.NoError(t, err)

	proofBytes, err := hex.DecodeString(
		strings.Trim(string(proofHex), "\n"),
	)
	require.NoError(t, err)

	p := &Proof{}
	err = p.Decode(bytes.NewReader(proofBytes))
	require.NoError(t, err)

	snapshot, err := p.Verify(context.Background(), nil, MockHeaderVerifier)
	require.NoError(t, err)
	require.NotNil(t, snapshot)
}

func BenchmarkProofEncoding(b *testing.B) {
	amt := uint64(5000)

	// Start with a minted genesis asset.
	genesisProof, _ := genRandomGenesisWithProof(
		b, asset.Normal, &amt, nil, false, nil, nil,
	)

	// We create a file with 10k proofs (the same one) and test encoding/
	// decoding performance.
	const numProofs = 10_000
	lotsOfProofs := make([]Proof, numProofs)
	for i := 0; i < numProofs; i++ {
		lotsOfProofs[i] = genesisProof
	}

	f, err := NewFile(V0, lotsOfProofs...)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()

	// Only this part is measured.
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		err = f.Encode(&buf)
		require.NoError(b, err)

		f2, err := NewFile(V0)
		require.NoError(b, err)

		err = f2.Decode(&buf)
		require.NoError(b, err)

		require.Len(b, f2.proofs, numProofs)
	}
}

// TestBIPTestVectors tests that the BIP test vectors are passing.
func TestBIPTestVectors(t *testing.T) {
	t.Parallel()

	for idx := range allTestVectorFiles {
		var (
			fileName    = allTestVectorFiles[idx]
			testVectors = &TestVectors{}
		)
		test.ParseTestVectors(t, fileName, &testVectors)
		t.Run(fileName, func(tt *testing.T) {
			tt.Parallel()

			runBIPTestVector(tt, testVectors)
		})
	}
}

// runBIPTestVector runs the tests in a single BIP test vector file.
func runBIPTestVector(t *testing.T, testVectors *TestVectors) {
	for _, validCase := range testVectors.ValidTestCases {
		validCase := validCase

		t.Run(validCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			p := validCase.Proof.ToProof(tt)

			var buf bytes.Buffer
			err := p.Encode(&buf)
			require.NoError(tt, err)

			areEqual := validCase.Expected == hex.EncodeToString(
				buf.Bytes(),
			)

			// Create nice diff if things don't match.
			if !areEqual {
				expectedProof := &Proof{}
				proofBytes, err := hex.DecodeString(
					strings.Trim(validCase.Expected, "\n"),
				)
				require.NoError(t, err)

				err = expectedProof.Decode(bytes.NewReader(
					proofBytes,
				))
				require.NoError(tt, err)

				require.Equal(tt, expectedProof, p)

				// Make sure we still fail the test.
				require.Equal(
					tt, validCase.Expected,
					hex.EncodeToString(buf.Bytes()),
				)
			}

			// We also want to make sure that the proof is decoded
			// correctly from the encoded TLV stream.
			decoded := &Proof{}
			err = decoded.Decode(hex.NewDecoder(
				strings.NewReader(validCase.Expected),
			))
			require.NoError(tt, err)

			require.Equal(tt, p, decoded)
		})
	}

	for _, invalidCase := range testVectors.ErrorTestCases {
		invalidCase := invalidCase

		t.Run(invalidCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			require.PanicsWithValue(tt, invalidCase.Error, func() {
				invalidCase.Proof.ToProof(tt)
			})
		})
	}
}

func init() {
	logWriter := build.NewRotatingLogWriter()
	logger := logWriter.GenSubLogger(Subsystem, func() {})
	logWriter.RegisterSubLogger(Subsystem, logger)
	UseLogger(logger)
}
