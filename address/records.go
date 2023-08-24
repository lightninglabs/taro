package address

import (
	"bytes"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightningnetwork/lnd/tlv"
)

// addressTlvType represents the different TLV types for Address TLV records.
type addressTLVType = tlv.Type

const (
	// addrVersionType is the TLV type of the addr version.
	addrVersionType addressTLVType = 0

	// addrAssetIDType is the TLV type of the asset ID.
	addrAssetIDType addressTLVType = 2

	// addrGroupKeyType is the TLV type of the group key of the asset.
	addrGroupKeyType addressTLVType = 3

	// addrScriptKeyType is the TLV type of the script key for the asset.
	addrScriptKeyType addressTLVType = 4

	// addrInternalKeyType is the TLV type of the internal key for the asset.
	addrInternalKeyType addressTLVType = 6

	// addrTapscriptSiblingType is the TLV type of the tapscript sibling for
	// the asset commitment.
	addrTapscriptSiblingType addressTLVType = 7

	// addrAmountType is the TLV type of the amount of the asset.
	addrAmountType addressTLVType = 8

	// addrProofCourierType is the TLV type of the proof courier address.
	addrProofCourierAddrType addressTLVType = 10

	// addrGroupSigType is the TLV type of the signature of the asset
	// genesis.
	//
	// NOTE: This field is optional. It is not included in the bech32m encoding
	// of the address.
	addrGroupSigType addressTLVType = 11

	// addrAssetGenType is the TLV type of the asset's genesis metadata.
	//
	// NOTE: This field is optional. It is not included in the bech32m encoding
	// of the address.
	addrAssetGenType addressTLVType = 13
)

func newAddressAssetVersionRecord(version *asset.Version) tlv.Record {
	return tlv.MakeStaticRecord(
		addrVersionType, version, 1, asset.VersionEncoder,
		asset.VersionDecoder,
	)
}

func newAddressAssetID(assetID *asset.ID) tlv.Record {
	return tlv.MakePrimitiveRecord(
		addrAssetIDType, (*[32]byte)(assetID),
	)
}

func newAddressGroupKeyRecord(groupKey **btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		addrGroupKeyType, groupKey, btcec.PubKeyBytesLenCompressed,
		asset.CompressedPubKeyEncoder, asset.CompressedPubKeyDecoder,
	)
}

func newAddressGroupSigRecord(groupSig **schnorr.Signature) tlv.Record {
	var addrBytes []byte
	if *groupSig != nil {
		addrBytes = (*groupSig).Serialize()
	}
	recordSize := tlv.SizeVarBytes(&addrBytes)

	return tlv.MakeDynamicRecord(
		addrGroupSigType, groupSig, recordSize,
		schnorrSigEncoder, schnorrSigDecoder,
	)
}

func newAddressScriptKeyRecord(scriptKey *btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		addrScriptKeyType, scriptKey, btcec.PubKeyBytesLenCompressed,
		compressedPubKeyEncoder, compressedPubKeyDecoder,
	)
}

func newAddressInternalKeyRecord(internalKey *btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		addrInternalKeyType, internalKey, btcec.PubKeyBytesLenCompressed,
		compressedPubKeyEncoder, compressedPubKeyDecoder,
	)
}

func newAddressTapscriptSiblingRecord(
	tapscriptSibling **commitment.TapscriptPreimage) tlv.Record {

	sizeFunc := func() uint64 {
		// 1 byte for the type, and then the pre-image itself.
		return 1 + uint64(len((*tapscriptSibling).SiblingPreimage))
	}
	return tlv.MakeDynamicRecord(
		addrTapscriptSiblingType, tapscriptSibling, sizeFunc,
		commitment.TapscriptPreimageEncoder,
		commitment.TapscriptPreimageDecoder,
	)
}

func newAddressAmountRecord(amount *uint64) tlv.Record {
	recordSize := func() uint64 {
		return tlv.VarIntSize(*amount)
	}
	return tlv.MakeDynamicRecord(
		addrAmountType, amount, recordSize,
		asset.VarIntEncoder, asset.VarIntDecoder,
	)
}

func newAssetGenesisRecord(genesis *asset.Genesis) tlv.Record {
	recordSize := func() uint64 {
		var (
			b   bytes.Buffer
			buf [8]byte
		)
		if err := asset.GenesisEncoder(&b, genesis, &buf); err != nil {
			panic(err)
		}
		return uint64(len(b.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		addrAssetGenType, genesis, recordSize,
		asset.GenesisEncoder, asset.GenesisDecoder,
	)
}

func newProofCourierAddrRecord(addr *url.URL) tlv.Record {
	var addrBytes []byte
	if addr != nil {
		addrBytes = []byte((*addr).String())
	}
	recordSize := tlv.SizeVarBytes(&addrBytes)

	return tlv.MakeDynamicRecord(
		addrProofCourierAddrType, addr, recordSize,
		urlEncoder, urlDecoder,
	)
}
