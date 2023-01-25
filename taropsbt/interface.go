package taropsbt

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightningnetwork/lnd/keychain"
)

// VPacket is a PSBT extension packet for a virtual transaction. It represents
// the virtual asset state transition as it will be validated by the Taro VM.
// Some elements within the virtual packet may refer to on-chain elements (such
// as the anchor BTC transaction that was used to anchor the input that is
// spent). But in general a virtual transaction does NOT directly map onto a BTC
// transaction. It is entirely possible that multiple virtual transactions will
// be merged into a single BTC transaction. Thus, each asset state transfer is
// represented in a virtual TX and multiple asset state transfers can be
// anchored within a single BTC transaction.
//
// TODO(guggero): Actually support merging multiple virtual transactions into a
// single BTC transaction.
type VPacket struct {
	// Input is the asset input that is being spent.
	//
	// TODO(guggero): Support spending multiple inputs.
	Input *VInput

	// Outputs is the list of new asset outputs that are created by the
	// virtual transaction. By convention the output at index 0 is the
	// change output for asset change or the asset tombstone in case of a
	// non-interactive full value send.
	Outputs []*VOutput

	// ChainParams are the Taro chain parameters that are used to encode and
	// decode certain contents of the virtual packet.
	ChainParams *address.ChainParams
}

// SetInputAsset sets the input asset that is being spent.
func (p *VPacket) SetInputAsset(a *asset.Asset) {
	p.Input.asset = a
	p.Input.serializeScriptKey(a.ScriptKey, p.ChainParams.HDCoinType)
}

// Anchor is a struct that contains all the information about an anchor output.
type Anchor struct {
	// Value is output value of the anchor output.
	Value btcutil.Amount

	// PkScript is the output script of the anchor output.
	PkScript []byte

	// SigHashType is the signature hash type that should be used to sign
	// the anchor output spend.
	SigHashType txscript.SigHashType

	// InternalKey is the internal key of the anchor output that the input
	// is spending the asset from.
	InternalKey *btcec.PublicKey

	// MerkleRoot is the root of the tap script merkle tree that also
	// contains the Taro commitment of the anchor output.
	MerkleRoot []byte

	// Bip32Derivation is the BIP32 derivation of the anchor output's
	// internal key.
	//
	// TODO(guggero): Do we also want to allow multiple derivations to be
	// specified here? That would allow us to specify multiple keys involved
	// in MuSig2 for example. Same for the Taproot derivation below.
	Bip32Derivation *psbt.Bip32Derivation

	// TrBip32Derivation is the Taproot BIP32 derivation of the anchor
	// output's internal key.
	TrBip32Derivation *psbt.TaprootBip32Derivation
}

// VInput represents an input to a virtual asset state transition transaction.
type VInput struct {
	// PInput is the embedded default PSBT input struct that is used for
	// asset related input data.
	psbt.PInput

	// PrevID is the asset previous ID of the asset being spent.
	PrevID asset.PrevID

	// Anchor contains the information about the BTC level anchor
	// transaction that committed to the asset being spent.
	Anchor Anchor

	// TapscriptSibling is the tapscript sibling of this asset. This will
	// usually be blank.
	TapscriptSibling []byte

	// asset is the full instance of the asset being spent. It is not
	// exported because the assets script key must be encoded in the PSBT
	// input struct for the signing to work correctly.
	asset *asset.Asset

	// IsSplit indicates whether the input asset is being split into more
	// than one piece. This is always true for non-interactive sends.
	IsSplit bool
}

// Asset returns the input's asset that's being spent.
func (i *VInput) Asset() *asset.Asset {
	return i.asset
}

// serializeScriptKey serializes the input asset's script key as the PSBT
// derivation information on the virtual input.
func (i *VInput) serializeScriptKey(key asset.ScriptKey, coinType uint32) {
	if key.TweakedScriptKey == nil {
		return
	}

	bip32Derivation, trBip32Derivation := Bip32DerivationFromKeyDesc(
		key.RawKey, coinType,
	)

	i.Bip32Derivation = []*psbt.Bip32Derivation{
		bip32Derivation,
	}
	i.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		trBip32Derivation,
	}
	i.TaprootInternalKey = trBip32Derivation.XOnlyPubKey
	i.TaprootMerkleRoot = key.Tweak
}

// deserializeScriptKey deserializes the PSBT derivation information on the
// input into the input asset's script key.
func (i *VInput) deserializeScriptKey() error {
	if i.asset == nil || len(i.TaprootInternalKey) == 0 ||
		len(i.Bip32Derivation) == 0 {

		return nil
	}

	bip32Derivation := i.Bip32Derivation[0]
	rawKeyDesc, err := KeyDescFromBip32Derivation(bip32Derivation)
	if err != nil {
		return fmt.Errorf("error decoding script key derivation info: "+
			"%w", err)
	}

	i.asset.ScriptKey.TweakedScriptKey = &asset.TweakedScriptKey{
		RawKey: rawKeyDesc,
		Tweak:  i.TaprootMerkleRoot,
	}

	return nil
}

// VOutput represents an output of a virtual asset state transition.
type VOutput struct {
	// Amount is the amount of units of the asset that this output is
	// creating. This can be zero in case of an asset tombstone in a
	// non-interactive full value send scenario. When serialized, this will
	// be stored as the value of the wire.TxOut of the PSBT's unsigned TX.
	Amount uint64

	// IsChange indicates whether this output is the change output for the
	// virtual transaction. By convention the first output of a virtual
	// asset transaction is always the change output, so this merely serves
	// as a more explicit way of indicating that.
	IsChange bool

	// Interactive, when set to true, indicates that the receiver of the
	// output is aware of the asset transfer and can therefore receive a
	// full value send directly and without a tombstone in the change
	// output.
	Interactive bool

	// AnchorOutputIndex indicates in which output index of the BTC
	// transaction this asset output should be committed to. Multiple asset
	// outputs can be committed to within the same BTC transaction output.
	AnchorOutputIndex uint32

	// AnchorOutputInternalKey is the internal key of the anchor output that
	// will be used to create the anchor Taproot output key to which this
	// asset output will be committed to.
	AnchorOutputInternalKey *btcec.PublicKey

	// AnchorOutputBip32Derivation is the BIP32 derivation of the anchor
	// output's internal key.
	AnchorOutputBip32Derivation *psbt.Bip32Derivation

	// AnchorOutputTaprootBip32Derivation is the Taproot BIP32 derivation of
	// the anchor output's internal key.
	AnchorOutputTaprootBip32Derivation *psbt.TaprootBip32Derivation

	// Asset is the actual asset (including witness or split commitment
	// data) that this output will commit to on chain. This asset will be
	// included in the proof sent to the recipient of this output.
	Asset *asset.Asset

	// ScriptKey is the new script key of the recipient of the asset. When
	// serialized, this will be stored in the TaprootInternalKey and
	// TaprootDerivationPath fields of the PSBT output.
	ScriptKey asset.ScriptKey
}

// SplitLocator creates a split locator from the output. The asset ID is passed
// in for cases in which the asset is not yet set on the output.
func (o *VOutput) SplitLocator(assetID asset.ID) commitment.SplitLocator {
	return commitment.SplitLocator{
		OutputIndex: o.AnchorOutputIndex,
		AssetID:     assetID,
		ScriptKey:   asset.ToSerialized(o.ScriptKey.PubKey),
		Amount:      o.Amount,
	}
}

// SetAnchorInternalKey sets the internal key and derivation path of the anchor
// output based on the given key descriptor and coin type.
func (o *VOutput) SetAnchorInternalKey(keyDesc keychain.KeyDescriptor,
	coinType uint32) {

	bip32Derivation, trBip32Derivation := Bip32DerivationFromKeyDesc(
		keyDesc, coinType,
	)
	o.AnchorOutputInternalKey = keyDesc.PubKey
	o.AnchorOutputBip32Derivation = bip32Derivation
	o.AnchorOutputTaprootBip32Derivation = trBip32Derivation
}

// AnchorKeyToDesc attempts to extract the key descriptor of the anchor output
// from the anchor output BIP32 derivation information.
func (o *VOutput) AnchorKeyToDesc() (keychain.KeyDescriptor, error) {
	if o.AnchorOutputBip32Derivation == nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("anchor output " +
			"bip32 derivation is missing")
	}

	return KeyDescFromBip32Derivation(o.AnchorOutputBip32Derivation)
}

// KeyDescFromBip32Derivation attempts to extract the key descriptor from the
// given public key and BIP32 derivation information.
func KeyDescFromBip32Derivation(
	bip32Derivation *psbt.Bip32Derivation) (keychain.KeyDescriptor, error) {

	if len(bip32Derivation.PubKey) == 0 {
		return keychain.KeyDescriptor{}, fmt.Errorf("pubkey is missing")
	}

	pubKey, err := btcec.ParsePubKey(bip32Derivation.PubKey)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("error parsing "+
			"pubkey: %w", err)
	}

	family, index, err := extractLocatorFromPath(bip32Derivation.Bip32Path)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("unable to "+
			"extract locator from path: %w", err)
	}

	return keychain.KeyDescriptor{
		PubKey: pubKey,
		KeyLocator: keychain.KeyLocator{
			Family: family,
			Index:  index,
		},
	}, nil
}

// Bip32DerivationFromKeyDesc returns the default and Taproot BIP32 key
// derivation information from the given key descriptor information.
func Bip32DerivationFromKeyDesc(keyDesc keychain.KeyDescriptor,
	coinType uint32) (*psbt.Bip32Derivation, *psbt.TaprootBip32Derivation) {

	bip32Derivation := &psbt.Bip32Derivation{
		PubKey: keyDesc.PubKey.SerializeCompressed(),
		Bip32Path: []uint32{
			keychain.BIP0043Purpose + hdkeychain.HardenedKeyStart,
			coinType + hdkeychain.HardenedKeyStart,
			uint32(keyDesc.Family) +
				uint32(hdkeychain.HardenedKeyStart),
			0,
			keyDesc.Index,
		},
	}

	return bip32Derivation, &psbt.TaprootBip32Derivation{
		XOnlyPubKey:          bip32Derivation.PubKey[1:],
		MasterKeyFingerprint: bip32Derivation.MasterKeyFingerprint,
		Bip32Path:            bip32Derivation.Bip32Path,
	}
}

// extractLocatorFromPath extracts the key family and index from the given BIP32
// derivation path.
func extractLocatorFromPath(path []uint32) (keychain.KeyFamily, uint32, error) {
	if len(path) != 5 {
		return 0, 0, fmt.Errorf("invalid bip32 derivation path "+
			"length: %d", len(path))
	}

	family := path[2] - hdkeychain.HardenedKeyStart
	index := path[4]

	return keychain.KeyFamily(family), index, nil
}
