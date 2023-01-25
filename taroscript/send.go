package taroscript

import (
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/taropsbt"
)

var (
	// ErrInvalidCollectibleSplit is returned when a collectible is split
	// into more than two outputs.
	ErrInvalidCollectibleSplit = errors.New(
		"fund: invalid collectible split",
	)

	// ErrInvalidChangeOutputLocation is returned when the change output is
	// not at the expected location (index 0).
	ErrInvalidChangeOutputLocation = errors.New(
		"fund: invalid change output location, should be index 0",
	)

	// ErrInvalidSplitAmounts is returned when the split amounts don't add
	// up to the amount of the asset being spent.
	ErrInvalidSplitAmounts = errors.New(
		"fund: invalid split amounts, sum doesn't match input",
	)
)

// PrepareOutputAssets prepares the assets of the given outputs depending on
// the amounts set on the transaction. If a split is necessary (non-interactive
// or partial amount send) it computes a split commitment with the given input
// and spend information. The input MUST be checked as valid beforehand and the
// change output is expected to be declared as such (and be at index 0).
func PrepareOutputAssets(input *taropsbt.VInput,
	outputs []*taropsbt.VOutput) error {

	// This should be caught way earlier but just to make sure that we never
	// overflow when converting the input amount to int64 we check this
	// again.
	inputAsset := input.Asset()
	if inputAsset.Amount > math.MaxInt64 {
		return fmt.Errorf("amount int64 overflow")
	}

	// A collectible cannot be split into individual pieces. So there can
	// only be a tombstone and a recipient output.
	if inputAsset.Type == asset.Collectible && len(outputs) > 2 {
		return ErrInvalidCollectibleSplit
	}

	var (
		residualAmount = inputAsset.Amount
		splitLocators  = make([]*commitment.SplitLocator, len(outputs))
	)
	for idx := range outputs {
		vOut := outputs[idx]

		// We assume the first output is the change output (or
		// tombstone if there is no change in a non-interactive send).
		if idx == 0 {
			// The change output should always be at index 0.
			if !vOut.IsChange {
				return ErrInvalidChangeOutputLocation
			}

			// A zero-amount change output (tombstone) must spend to
			// the un-spendable NUMS script key.
			if vOut.Amount == 0 &&
				!vOut.ScriptKey.PubKey.IsEqual(asset.NUMSPubKey) {

				return commitment.ErrInvalidScriptKey
			}
		} else {
			if vOut.IsChange {
				return ErrInvalidChangeOutputLocation
			}
		}

		residualAmount -= vOut.Amount

		locator := vOut.SplitLocator(inputAsset.ID())
		splitLocators[idx] = &locator
	}

	// We should now have exactly zero value left over after splitting.
	if residualAmount != 0 {
		return ErrInvalidSplitAmounts
	}

	// If we have an interactive full value send, we don't need a tomb stone
	// at all.
	inputIDCopy := input.PrevID
	if interactiveFullValueSend(input, outputs) {
		// We'll now create a new copy of the old asset, swapping out
		// the script key. We blank out the tweaked key information as
		// this is now an external asset.
		outputs[1].Asset = inputAsset.Copy()
		outputs[1].Asset.ScriptKey = outputs[1].ScriptKey

		// Record the PrevID of the input asset in a Witness for the new
		// asset. This Witness still needs a valid signature for the new
		// asset to be valid.
		//
		// TODO(roasbeef): when we fix #121, then this should also be a
		// ZeroPrevID
		outputs[1].Asset.PrevWitnesses = []asset.Witness{
			{
				PrevID:          &inputIDCopy,
				TxWitness:       nil,
				SplitCommitment: nil,
			},
		}

		// We are done, since we don't need to create a split
		// commitment.
		return nil
	}

	splitCommitment, err := commitment.NewSplitCommitment(
		inputAsset, input.PrevID.OutPoint, splitLocators[0],
		splitLocators[1:]...,
	)
	if err != nil {
		return err
	}

	// Assign each of the split assets to their respective outputs.
	input.IsSplit = true
	for idx := range outputs {
		// The change output for a split asset send always gets the root
		// asset committed, even if it's a zero value (tombstone) split
		// output for the sender.
		if outputs[idx].IsChange {
			outputs[idx].Asset = splitCommitment.RootAsset.Copy()
			continue
		}

		locator := splitLocators[idx]
		splitAsset, ok := splitCommitment.SplitAssets[*locator]
		if !ok {
			return fmt.Errorf("invalid split, asset for locator "+
				"%v not found", locator)
		}

		outputs[idx].Asset = &splitAsset.Asset
		outputs[idx].Asset.ScriptKey = outputs[idx].ScriptKey
	}

	return nil
}

// SignVirtualTransaction updates the new asset (the root asset located at the
// change output in case of a non-interactive or partial amount send or the
// full asset in case of an interactive full amount send) by creating a
// signature over the asset transfer, verifying the transfer with the Taro VM,
// and attaching that signature to the new Asset.
func SignVirtualTransaction(input *taropsbt.VInput, outputs []*taropsbt.VOutput,
	signer Signer, validator TxValidator) error {

	prevAssets := commitment.InputSet{
		input.PrevID: input.Asset(),
	}
	newAsset := outputs[1].Asset
	if input.IsSplit {
		newAsset = outputs[0].Asset
	}

	// Create a Taro virtual transaction representing the asset transfer.
	virtualTx, _, err := VirtualTx(newAsset, prevAssets)
	if err != nil {
		return err
	}

	// For each input asset leaf, we need to produce a witness. Update the
	// input of the virtual TX, generate a witness, and attach it to the
	// copy of the new Asset.
	//
	// TODO(guggero): I think this is wrong... We shouldn't look at
	// PrevWitnesses of the single asset we spend but instead have multiple
	// inputs if we want to spend multiple coins of the same asset?
	prevWitnessCount := len(newAsset.PrevWitnesses)
	for idx := 0; idx < prevWitnessCount; idx++ {
		prevAssetID := newAsset.PrevWitnesses[idx].PrevID
		prevAsset := prevAssets[*prevAssetID]
		virtualTxCopy := VirtualTxWithInput(
			virtualTx, prevAsset, uint32(idx), nil,
		)

		newWitness, err := SignTaprootKeySpend(
			*input.Asset().ScriptKey.RawKey.PubKey, virtualTxCopy,
			prevAsset, 0, txscript.SigHashDefault, signer,
		)
		if err != nil {
			return err
		}

		newAsset.PrevWitnesses[idx].TxWitness = *newWitness
	}

	// Create an instance of the Taro VM and validate the transfer.
	verifySpend := func(splitAssets []*commitment.SplitAsset) error {
		newAssetCopy := newAsset.Copy()
		err := validator.Execute(newAssetCopy, splitAssets, prevAssets)
		if err != nil {
			return err
		}
		return nil
	}

	// If the transfer contains no asset splits, we only need to validate
	// the new asset with its witness attached.
	if !input.IsSplit {
		if err := verifySpend(nil); err != nil {
			return err
		}

		return nil
	}

	// If the transfer includes an asset split, we have to validate each
	// split asset to ensure that our new Asset is committing to
	// a valid SplitCommitment.
	splitAssets := make([]*commitment.SplitAsset, 0, len(outputs)-1)
	for idx := range outputs {
		if outputs[idx].IsChange || outputs[idx].Interactive {
			continue
		}

		splitAssets = append(splitAssets, &commitment.SplitAsset{
			Asset:       *outputs[idx].Asset,
			OutputIndex: outputs[idx].AnchorOutputIndex,
		})
	}
	if err := verifySpend(splitAssets); err != nil {
		return err
	}

	// Update each split asset to store the root asset with the witness
	// attached, so the receiver can verify inclusion of the root asset.
	for idx := range outputs {
		if outputs[idx].IsChange || outputs[idx].Interactive {
			continue
		}

		splitAsset := outputs[idx].Asset
		splitCommitment := splitAsset.PrevWitnesses[0].SplitCommitment
		splitCommitment.RootAsset = *newAsset.Copy()
	}

	return nil
}

// interactiveFullValueSend returns true if the given outputs spend the input
// fully and interactively.
func interactiveFullValueSend(input *taropsbt.VInput,
	outputs []*taropsbt.VOutput) bool {

	return len(outputs) == 2 &&
		outputs[1].Amount == input.Asset().Amount &&
		outputs[1].Interactive
}
