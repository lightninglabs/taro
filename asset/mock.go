package asset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/input"
	"github.com/stretchr/testify/require"
)

// RandGenesis creates a random genesis for testing.
func RandGenesis(t testing.TB, assetType Type) Genesis {
	t.Helper()

	var metaHash [32]byte
	test.RandRead(t, metaHash[:])

	return Genesis{
		FirstPrevOut: test.RandOp(t),
		Tag:          hex.EncodeToString(metaHash[:]),
		MetaHash:     metaHash,
		OutputIndex:  uint32(test.RandInt[int32]()),
		Type:         assetType,
	}
}

// RandGroupKey creates a random group key for testing.
func RandGroupKey(t testing.TB, genesis Genesis) *GroupKey {
	groupKey, _ := RandGroupKeyWithSigner(t, genesis)
	return groupKey
}

// RandGroupKeyWithSigner creates a random group key for testing, and provides
// the signer for reissuing assets into the same group.
func RandGroupKeyWithSigner(t testing.TB, genesis Genesis) (*GroupKey, []byte) {
	privateKey := test.RandPrivKey(t)

	genSigner := NewRawKeyGenesisSigner(privateKey)
	genBuilder := RawGroupTxBuilder{}
	groupKey, err := DeriveGroupKey(
		genSigner, &genBuilder, test.PubToKeyDesc(privateKey.PubKey()),
		genesis, nil,
	)
	require.NoError(t, err)

	return groupKey, privateKey.Serialize()
}

// Copied from tapscript/tx.go.
func virtualGenesisTxWithInput(virtualTx *wire.MsgTx, input *Asset,
	idx uint32, witness wire.TxWitness) *wire.MsgTx {

	txCopy := virtualTx.Copy()
	txCopy.LockTime = uint32(input.LockTime)
	// Using the standard zeroIndex for virtual prev outs.
	txCopy.TxIn[0].PreviousOutPoint.Index = idx
	txCopy.TxIn[0].Sequence = uint32(input.RelativeLockTime)
	txCopy.TxIn[0].Witness = witness
	return txCopy
}

// Copied from tapscript/tx.go.
func inputGenesisAssetPrevOut(prevAsset Asset) (*wire.TxOut, error) {
	switch prevAsset.ScriptVersion {
	case ScriptV0:
		// If the input asset is a genesis asset that is part of an
		// asset group, we need to validate the group witness against
		// the tweaked group key and not the genesis asset script key.
		validationKey := &prevAsset.GroupKey.GroupPubKey
		pkScript, err := test.ComputeTaprootScriptErr(
			schnorr.SerializePubKey(validationKey),
		)
		if err != nil {
			return nil, err
		}

		return &wire.TxOut{
			Value:    int64(prevAsset.Amount),
			PkScript: pkScript,
		}, nil
	default:
		return nil, ErrUnknownVersion
	}
}

// Forked from tapscript/tx/virtualTxIn to remove checks for non-nil PrevIDs on
// inputs and full consumption of inputs.
func VirtualGenesisTxIn(newAsset *Asset) (*wire.TxIn, mssmt.Tree, error) {
	inputTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	// TODO(bhandras): thread the context through.
	ctx := context.TODO()

	key := ZeroPrevID.Hash()
	leaf, err := newAsset.Leaf()
	if err != nil {
		return nil, nil, err
	}

	_, err = inputTree.Insert(ctx, key, leaf)
	if err != nil {
		return nil, nil, err
	}

	treeRoot, err := inputTree.Root(context.Background())
	if err != nil {
		return nil, nil, err
	}

	// Re-implement tapscript/tx/virtualTxInPrevOut directly here.
	// TODO(roasbeef): document empty hash usage here
	virtualTxInPrevOut := func(root mssmt.Node) *wire.OutPoint {
		// Grab the hash digest of the SMT node. This'll be used to
		// generate the virtual prev out for this tx in.
		//
		// TODO(roasbeef): this already contains the sum, so can just
		// use it directly?
		rootKey := root.NodeHash()

		// Map this to: nodeHash || nodeSum.
		h := sha256.New()
		_, _ = h.Write(rootKey[:])
		_ = binary.Write(h, binary.BigEndian, root.NodeSum())

		// Using the standard zeroIndex for virtual prev outs.
		return wire.NewOutPoint(
			(*chainhash.Hash)(h.Sum(nil)), 0,
		)
	}
	prevOut := virtualTxInPrevOut(treeRoot)

	return wire.NewTxIn(prevOut, nil, nil), inputTree, nil
}

// Forked from tapscript/tx/virtualTxOut to remove checks for split commitments
// and witness stripping.
func virtualGenesisTxOut(newAsset *Asset) (*wire.TxOut, error) {
	// Commit to the new asset directly. In this case, the output script is
	// derived from the root of a MS-SMT containing the new asset.
	groupKey := schnorr.SerializePubKey(&newAsset.GroupKey.GroupPubKey)
	assetID := newAsset.Genesis.ID()

	h := sha256.New()
	_, _ = h.Write(groupKey)
	_, _ = h.Write(assetID[:])
	_, _ = h.Write(schnorr.SerializePubKey(newAsset.ScriptKey.PubKey))

	key := *(*[32]byte)(h.Sum(nil))
	leaf, err := newAsset.Leaf()
	if err != nil {
		return nil, err
	}
	outputTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	// TODO(bhandras): thread the context through.
	tree, err := outputTree.Insert(context.TODO(), key, leaf)
	if err != nil {
		return nil, err
	}

	treeRoot, err := tree.Root(context.Background())
	if err != nil {
		return nil, err
	}

	rootKey := treeRoot.NodeHash()
	pkScript, err := test.ComputeTaprootScriptErr(rootKey[:])
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(int64(newAsset.Amount), pkScript), nil
}

// Forked from tapscript/tx/virtualTx to be used only with the
// RawGroupTxBuilder.
func virtualGenesisTx(newAsset *Asset) (*wire.MsgTx, error) {
	var (
		txIn *wire.TxIn
		err  error
	)

	// We'll start by mapping all inputs into a MS-SMT.
	txIn, _, err = VirtualGenesisTxIn(newAsset)
	if err != nil {
		return nil, err
	}

	// Then we'll map all asset outputs into a single UTXO.
	txOut, err := virtualGenesisTxOut(newAsset)
	if err != nil {
		return nil, err
	}

	// With our single input and output mapped, we're ready to construct our
	// virtual transaction.
	virtualTx := wire.NewMsgTx(2)
	virtualTx.AddTxIn(txIn)
	virtualTx.AddTxOut(txOut)
	return virtualTx, nil
}

// SignOutputRaw creates a signature for a single input.
// Taken from lnd/lnwallet/btcwallet/signer:L344, SignOutputRaw
func SignOutputRaw(priv *btcec.PrivateKey, tx *wire.MsgTx,
	signDesc *input.SignDescriptor) (*schnorr.Signature, error) {

	witnessScript := signDesc.WitnessScript

	privKey := priv
	var maybeTweakPrivKey *btcec.PrivateKey

	switch {
	case signDesc.SingleTweak != nil:
		maybeTweakPrivKey = input.TweakPrivKey(
			privKey, signDesc.SingleTweak,
		)

	case signDesc.DoubleTweak != nil:
		maybeTweakPrivKey = input.DeriveRevocationPrivKey(
			privKey, signDesc.DoubleTweak,
		)

	default:
		maybeTweakPrivKey = privKey
	}

	privKey = maybeTweakPrivKey

	// In case of a taproot output any signature is always a Schnorr
	// signature, based on the new tapscript sighash algorithm.
	if !txscript.IsPayToTaproot(signDesc.Output.PkScript) {
		return nil, fmt.Errorf("mock signer: output script not taproot")
	}

	sigHashes := txscript.NewTxSigHashes(
		tx, signDesc.PrevOutputFetcher,
	)

	// Are we spending a script path or the key path? The API is slightly
	// different, so we need to account for that to get the raw signature.
	var (
		rawSig []byte
		err    error
	)
	switch signDesc.SignMethod {
	case input.TaprootKeySpendBIP0086SignMethod,
		input.TaprootKeySpendSignMethod:

		// This function tweaks the private key using the tap root key
		// supplied as the tweak.
		rawSig, err = txscript.RawTxInTaprootSignature(
			tx, sigHashes, signDesc.InputIndex,
			signDesc.Output.Value, signDesc.Output.PkScript,
			signDesc.TapTweak, signDesc.HashType, privKey,
		)

	case input.TaprootScriptSpendSignMethod:
		leaf := txscript.TapLeaf{
			LeafVersion: txscript.BaseLeafVersion,
			Script:      witnessScript,
		}
		rawSig, err = txscript.RawTxInTapscriptSignature(
			tx, sigHashes, signDesc.InputIndex,
			signDesc.Output.Value, signDesc.Output.PkScript,
			leaf, signDesc.HashType, privKey,
		)
	}
	if err != nil {
		return nil, err
	}

	return schnorr.ParseSignature(rawSig)
}

func SignVirtualTx(priv *btcec.PrivateKey, signDesc *lndclient.SignDescriptor,
	tx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature, error) {

	prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)

	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

	fullSignDesc := input.SignDescriptor{
		KeyDesc:           signDesc.KeyDesc,
		SingleTweak:       signDesc.SingleTweak,
		DoubleTweak:       signDesc.DoubleTweak,
		TapTweak:          signDesc.TapTweak,
		WitnessScript:     signDesc.WitnessScript,
		SignMethod:        signDesc.SignMethod,
		Output:            signDesc.Output,
		HashType:          signDesc.HashType,
		SigHashes:         sigHashes,
		PrevOutputFetcher: prevOutFetcher,
		InputIndex:        signDesc.InputIndex,
	}

	sig, err := SignOutputRaw(priv, tx, &fullSignDesc)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// RandScriptKey creates a random script key for testing.
func RandScriptKey(t testing.TB) ScriptKey {
	return NewScriptKey(test.RandPrivKey(t).PubKey())
}

// RandSerializedKey creates a random serialized key for testing.
func RandSerializedKey(t testing.TB) SerializedKey {
	return ToSerialized(test.RandPrivKey(t).PubKey())
}

// RandID creates a random asset ID.
func RandID(t testing.TB) ID {
	var a ID
	test.RandRead(t, a[:])

	return a
}

// RandAsset creates a random asset of the given type for testing.
func RandAsset(t testing.TB, assetType Type) *Asset {
	t.Helper()

	genesis := RandGenesis(t, assetType)
	familyKey := RandGroupKey(t, genesis)
	scriptKey := RandScriptKey(t)

	return RandAssetWithValues(t, genesis, familyKey, scriptKey)
}

// RandAssetWithValues creates a random asset with the given genesis and keys
// for testing.
func RandAssetWithValues(t testing.TB, genesis Genesis, groupKey *GroupKey,
	scriptKey ScriptKey) *Asset {

	t.Helper()

	units := test.RandInt[uint64]() + 1

	switch genesis.Type {
	case Normal:

	case Collectible:
		units = 1

	default:
		t.Fatal("unhandled asset type", genesis.Type)
	}

	a, err := New(genesis, units, 0, 0, scriptKey, groupKey)
	require.NoError(t, err)

	return a
}

type ValidTestCase struct {
	Asset    *TestAsset `json:"asset"`
	Expected string     `json:"expected"`
	Comment  string     `json:"comment"`
}

type ErrorTestCase struct {
	Asset   *TestAsset `json:"asset"`
	Error   string     `json:"error"`
	Comment string     `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}

func NewTestFromAsset(t testing.TB, a *Asset) *TestAsset {
	ta := &TestAsset{
		Version:             uint8(a.Version),
		GenesisFirstPrevOut: a.Genesis.FirstPrevOut.String(),
		GenesisTag:          a.Genesis.Tag,
		GenesisMetaHash:     hex.EncodeToString(a.Genesis.MetaHash[:]),
		GenesisOutputIndex:  a.Genesis.OutputIndex,
		GenesisType:         uint8(a.Genesis.Type),
		Amount:              a.Amount,
		LockTime:            a.LockTime,
		RelativeLockTime:    a.RelativeLockTime,
		ScriptVersion:       uint16(a.ScriptVersion),
		ScriptKey:           test.HexPubKey(a.ScriptKey.PubKey),
	}

	for _, w := range a.PrevWitnesses {
		ta.PrevWitnesses = append(
			ta.PrevWitnesses, NewTestFromWitness(t, w),
		)
	}

	if a.SplitCommitmentRoot != nil {
		ta.SplitCommitmentRoot = mssmt.NewTestFromNode(
			t, a.SplitCommitmentRoot,
		)
	}

	if a.GroupKey != nil {
		ta.GroupKey = NewTestFromGroupKey(t, a.GroupKey)
	}

	return ta
}

type TestAsset struct {
	Version             uint8           `json:"version"`
	GenesisFirstPrevOut string          `json:"genesis_first_prev_out"`
	GenesisTag          string          `json:"genesis_tag"`
	GenesisMetaHash     string          `json:"genesis_meta_hash"`
	GenesisOutputIndex  uint32          `json:"genesis_output_index"`
	GenesisType         uint8           `json:"genesis_type"`
	Amount              uint64          `json:"amount"`
	LockTime            uint64          `json:"lock_time"`
	RelativeLockTime    uint64          `json:"relative_lock_time"`
	PrevWitnesses       []*TestWitness  `json:"prev_witnesses"`
	SplitCommitmentRoot *mssmt.TestNode `json:"split_commitment_root"`
	ScriptVersion       uint16          `json:"script_version"`
	ScriptKey           string          `json:"script_key"`
	GroupKey            *TestGroupKey   `json:"group_key"`
}

func (ta *TestAsset) ToAsset(t testing.TB) *Asset {
	t.Helper()

	// Validate minimum fields are set. We use panic, so we can actually
	// interpret the error message in the error test cases.
	if ta.GenesisFirstPrevOut == "" || ta.GenesisMetaHash == "" {
		panic("missing genesis fields")
	}

	if ta.ScriptKey == "" {
		panic("missing script key")
	}

	if len(ta.ScriptKey) != test.HexCompressedPubKeyLen {
		panic("invalid script key length")
	}

	if ta.GroupKey != nil {
		if ta.GroupKey.GroupKey == "" {
			panic("missing group key")
		}

		if len(ta.GroupKey.GroupKey) != test.HexCompressedPubKeyLen {
			panic("invalid group key length")
		}
	}

	a := &Asset{
		Version: Version(ta.Version),
		Genesis: Genesis{
			FirstPrevOut: test.ParseOutPoint(
				t, ta.GenesisFirstPrevOut,
			),
			Tag:         ta.GenesisTag,
			MetaHash:    test.Parse32Byte(t, ta.GenesisMetaHash),
			OutputIndex: ta.GenesisOutputIndex,
			Type:        Type(ta.GenesisType),
		},
		Amount:           ta.Amount,
		LockTime:         ta.LockTime,
		RelativeLockTime: ta.RelativeLockTime,
		ScriptVersion:    ScriptVersion(ta.ScriptVersion),
		ScriptKey: ScriptKey{
			PubKey: test.ParsePubKey(t, ta.ScriptKey),
		},
	}

	for _, tw := range ta.PrevWitnesses {
		a.PrevWitnesses = append(
			a.PrevWitnesses, tw.ToWitness(t),
		)
	}

	if ta.SplitCommitmentRoot != nil {
		a.SplitCommitmentRoot = ta.SplitCommitmentRoot.ToNode(t)
	}

	if ta.GroupKey != nil {
		a.GroupKey = ta.GroupKey.ToGroupKey(t)
	}

	return a
}

func NewTestFromWitness(t testing.TB, w Witness) *TestWitness {
	t.Helper()

	tw := &TestWitness{}

	if w.PrevID != nil {
		tw.PrevID = NewTestFromPrevID(w.PrevID)
	}

	for _, witness := range w.TxWitness {
		tw.TxWitness = append(tw.TxWitness, hex.EncodeToString(witness))
	}

	if w.SplitCommitment != nil {
		tw.SplitCommitment = NewTestFromSplitCommitment(
			t, w.SplitCommitment,
		)
	}

	return tw
}

type TestWitness struct {
	PrevID          *TestPrevID          `json:"prev_id"`
	TxWitness       []string             `json:"tx_witness"`
	SplitCommitment *TestSplitCommitment `json:"split_commitment"`
}

func (tw *TestWitness) ToWitness(t testing.TB) Witness {
	t.Helper()

	w := Witness{}
	if tw.PrevID != nil {
		w.PrevID = tw.PrevID.ToPrevID(t)
	}

	for _, witness := range tw.TxWitness {
		w.TxWitness = append(w.TxWitness, test.ParseHex(t, witness))
	}

	if tw.SplitCommitment != nil {
		w.SplitCommitment = tw.SplitCommitment.ToSplitCommitment(t)
	}

	return w
}

func NewTestFromPrevID(prevID *PrevID) *TestPrevID {
	return &TestPrevID{
		OutPoint:  prevID.OutPoint.String(),
		AssetID:   hex.EncodeToString(prevID.ID[:]),
		ScriptKey: hex.EncodeToString(prevID.ScriptKey[:]),
	}
}

type TestPrevID struct {
	OutPoint  string `json:"out_point"`
	AssetID   string `json:"asset_id"`
	ScriptKey string `json:"script_key"`
}

func (tpv *TestPrevID) ToPrevID(t testing.TB) *PrevID {
	if tpv.OutPoint == "" || tpv.AssetID == "" || tpv.ScriptKey == "" {
		return nil
	}

	return &PrevID{
		OutPoint:  test.ParseOutPoint(t, tpv.OutPoint),
		ID:        test.Parse32Byte(t, tpv.AssetID),
		ScriptKey: test.Parse33Byte(t, tpv.ScriptKey),
	}
}

func NewTestFromSplitCommitment(t testing.TB,
	sc *SplitCommitment) *TestSplitCommitment {

	t.Helper()

	var buf bytes.Buffer
	err := sc.Proof.Compress().Encode(&buf)
	require.NoError(t, err)

	return &TestSplitCommitment{
		Proof:     hex.EncodeToString(buf.Bytes()),
		RootAsset: NewTestFromAsset(t, &sc.RootAsset),
	}
}

type TestSplitCommitment struct {
	Proof     string     `json:"proof"`
	RootAsset *TestAsset `json:"root_asset"`
}

func (tsc *TestSplitCommitment) ToSplitCommitment(
	t testing.TB) *SplitCommitment {

	t.Helper()

	sc := &SplitCommitment{
		Proof: mssmt.ParseProof(t, tsc.Proof),
	}
	if tsc.RootAsset != nil {
		sc.RootAsset = *tsc.RootAsset.ToAsset(t)
	}

	return sc
}

func NewTestFromGroupKey(t testing.TB, gk *GroupKey) *TestGroupKey {
	t.Helper()

	return &TestGroupKey{
		GroupKey: test.HexPubKey(&gk.GroupPubKey),
	}
}

type TestGroupKey struct {
	GroupKey string `json:"group_key"`
}

func (tgk *TestGroupKey) ToGroupKey(t testing.TB) *GroupKey {
	t.Helper()

	return &GroupKey{
		GroupPubKey: *test.ParsePubKey(t, tgk.GroupKey),
	}
}

type TestScriptKey struct {
}
