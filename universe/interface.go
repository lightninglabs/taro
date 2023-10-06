package universe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
)

var (
	// ErrNoUniverseRoot is returned when no universe root is found.
	ErrNoUniverseRoot = fmt.Errorf("no universe root found")

	// ErrNoUniverseServers is returned when no active Universe servers are
	// found in the DB.
	ErrNoUniverseServers = fmt.Errorf("no active federation servers")

	// ErrDuplicateUniverse is returned when the Universe server being added
	// to the DB already exists.
	ErrDuplicateUniverse = fmt.Errorf("universe server already added")

	// ErrNoUniverseProofFound is returned when a user attempts to look up
	// a key in the universe that actually points to the empty leaf.
	ErrNoUniverseProofFound = fmt.Errorf("no universe proof found")
)

// Identifier is the identifier for a universe.
type Identifier struct {
	// AssetID is the asset ID for the universe.
	//
	// TODO(roasbeef): make both pointers?
	AssetID asset.ID

	// GroupKey is the group key for the universe.
	GroupKey *btcec.PublicKey

	// ProofType is the type of proof that should be stored in the universe.
	ProofType ProofType
}

// Bytes returns a bytes representation of the ID.
func (i *Identifier) Bytes() [32]byte {
	if i.GroupKey != nil {
		return sha256.Sum256(schnorr.SerializePubKey(i.GroupKey))
	}

	return i.AssetID
}

// String returns a string representation of the ID.
func (i *Identifier) String() string {
	// The namespace is prefixed by the proof type. This is done to make it
	// easier to identify the proof type when looking at a list of
	// namespaces (say, in a DB explorer).
	return fmt.Sprintf("%s-%x", i.ProofType, i.Bytes())
}

// StringForLog returns a string representation of the ID for logging.
func (i *Identifier) StringForLog() string {
	groupKey := "<nil>"
	if i.GroupKey != nil {
		groupKey = hex.EncodeToString(
			schnorr.SerializePubKey(i.GroupKey),
		)
	}

	return fmt.Sprintf("%v (asset_id=%x, group_key=%v, proof_type=%v)",
		i.String(), i.AssetID[:], groupKey, i.ProofType)
}

// ValidateProofUniverseType validates that the proof type matches the universe
// identifier proof type.
func ValidateProofUniverseType(proof *proof.Proof, uniID Identifier) error {
	expectedProofType, err := NewProofTypeFromAssetProof(proof)
	if err != nil {
		return err
	}

	if expectedProofType != uniID.ProofType {
		return fmt.Errorf("proof type mismatch: expected %s, got %s",
			expectedProofType, uniID.ProofType)
	}

	return nil
}

// GenesisWithGroup is a two tuple that groups the genesis of an asset with the
// group key it's associated with (if that exists).
type GenesisWithGroup struct {
	asset.Genesis

	*asset.GroupKey
}

// Leaf is a leaf node in the SMT that represents an asset issuance or transfer.
// For each asset issued or transferred for a given universe, a new leaf is
// created.
type Leaf struct {
	GenesisWithGroup

	// Proof is either an issuance proof or a transfer proof associated with
	// the issuance or spend event which this leaf represents.
	Proof *proof.Proof

	// Amt is the amount of units associated with the coin.
	Amt uint64
}

// SmtLeafNode returns the SMT leaf node for the given leaf.
func (m *Leaf) SmtLeafNode() (*mssmt.LeafNode, error) {
	var buf bytes.Buffer
	if err := m.Proof.Encode(&buf); err != nil {
		return nil, err
	}

	return mssmt.NewLeafNode(buf.Bytes(), m.Amt), nil
}

// LeafKey is the top level leaf key for a universe. This will be used to key
// into a universe's MS-SMT data structure. The final serialized key is:
// sha256(mintingOutpoint || scriptKey). This ensures that all
// leaves for a given asset will be uniquely keyed in the universe tree.
type LeafKey struct {
	// OutPoint is the outpoint at which the asset referenced by this key
	// resides.
	OutPoint wire.OutPoint

	// ScriptKey is the script key of the base asset. If this isn't
	// specified, then the caller is attempting to query for all the script
	// keys at that minting outpoint.
	ScriptKey *asset.ScriptKey

	// TODO(roasbeef): add asset type too?
}

// UniverseKey is the key for a universe.
func (b LeafKey) UniverseKey() [32]byte {
	// key = sha256(mintingOutpoint || scriptKey)
	h := sha256.New()
	_ = wire.WriteOutPoint(h, 0, 0, &b.OutPoint)
	h.Write(schnorr.SerializePubKey(b.ScriptKey.PubKey))

	var k [32]byte
	copy(k[:], h.Sum(nil))

	return k
}

// Proof associates a universe leaf (and key) with its corresponding multiverse
// and universe inclusion proofs.
//
// These inclusion proofs can be used to verify that a valid asset exists
// (based on the proof in the leaf), and that the asset is committed to within
// the universe root and multiverse root.
type Proof struct {
	// Leaf is the leaf node for the asset within the universe tree.
	Leaf *Leaf

	// LeafKey is the universe leaf key for the asset issuance or spend.
	LeafKey LeafKey

	// UniverseRoot is the root of the universe that the asset is located
	// within.
	UniverseRoot mssmt.Node

	// UniverseInclusionProof is the universe inclusion proof for the asset
	// within the universe tree.
	UniverseInclusionProof *mssmt.Proof

	// MultiverseRoot is the root of the multiverse tree that the asset is
	// located within.
	MultiverseRoot mssmt.Node

	// MultiverseInclusionProof is the inclusion proof for the asset within
	// the multiverse tree.
	MultiverseInclusionProof *mssmt.Proof
}

// VerifyRoot verifies that the inclusion proof for the root node matches the
// specified root. This is useful for sanity checking an issuance proof against
// the purported root, and the included leaf.
func (i *Proof) VerifyRoot(expectedRoot mssmt.Node) (bool, error) {
	leafNode, err := i.Leaf.SmtLeafNode()
	if err != nil {
		return false, err
	}

	reconstructedRoot := i.UniverseInclusionProof.Root(
		i.LeafKey.UniverseKey(), leafNode,
	)

	return mssmt.IsEqualNode(i.UniverseRoot, expectedRoot) &&
		mssmt.IsEqualNode(reconstructedRoot, expectedRoot), nil
}

// BaseBackend is the backend storage interface for a base universe. The
// backend can be used to store issuance profs, retrieve them, and also fetch
// the set of keys and leaves stored within the universe.
//
// TODO(roasbeef): gRPC service to match this, think about the REST mapping
type BaseBackend interface {
	// RootNode returns the root node for a given base universe.
	RootNode(context.Context) (mssmt.Node, string, error)

	// RegisterIssuance inserts a new minting leaf within the universe
	// tree, stored at the base key. The metaReveal type is purely
	// optional, and should be specified if the genesis proof committed to
	// a non-zero meta hash.
	RegisterIssuance(ctx context.Context, key LeafKey, leaf *Leaf,
		metaReveal *proof.MetaReveal) (*Proof, error)

	// FetchIssuanceProof returns an issuance proof for the target key. If
	// the key doesn't have a script key specified, then all the proofs for
	// the minting outpoint will be returned. If neither are specified,
	// then proofs for all the inserted leaves will be returned.
	//
	// TODO(roasbeef): can eventually do multi-proofs for the SMT
	FetchIssuanceProof(ctx context.Context,
		key LeafKey) ([]*Proof, error)

	// MintingKeys returns all the keys inserted in the universe.
	MintingKeys(ctx context.Context) ([]LeafKey, error)

	// MintingLeaves returns all the minting leaves inserted into the
	// universe.
	MintingLeaves(ctx context.Context) ([]Leaf, error)

	// DeleteUniverse deletes all leaves, and the root, for a given base
	// universe.
	DeleteUniverse(ctx context.Context) (string, error)
}

// BaseRoot is the ms-smt root for a base universe. This root can be used to
// compare against other trackers of a base universe to find discrepancies
// (unknown issuance events, etc).
type BaseRoot struct {
	ID Identifier

	mssmt.Node

	// AssetName is the name of the asset. This might not always be set for
	// performance reasons.
	AssetName string

	// GroupedAssets is an optional map of asset IDs to the minted amount.
	// This is only set for grouped assets.
	GroupedAssets map[asset.ID]uint64
}

// MultiverseArchive is an interface used to keep track of the set of universe
// roots that we know of. The BaseBackend interface is used to interact with a
// particular base universe, while this is used to obtain aggregate information
// about the universes.
type MultiverseArchive interface {
	// RootNodes returns the complete set of known root nodes for the set
	// of assets tracked in the base Universe.
	RootNodes(ctx context.Context) ([]BaseRoot, error)

	// UpsertProofLeaf upserts a proof leaf within the multiverse tree and
	// the universe tree that corresponds to the given key.
	UpsertProofLeaf(ctx context.Context, id Identifier, key LeafKey,
		leaf *Leaf,
		metaReveal *proof.MetaReveal) (*Proof, error)

	// RegisterBatchIssuance inserts a new minting leaf batch within the
	// multiverse tree and the universe tree that corresponds to the given
	// base key(s).
	RegisterBatchIssuance(ctx context.Context, items []*IssuanceItem) error

	// FetchProofLeaf returns a proof leaf for the target key. If the key
	// doesn't have a script key specified, then all the proof leafs for the
	// minting outpoint will be returned. If neither are specified, then all
	// inserted proof leafs will be returned.
	FetchProofLeaf(ctx context.Context, id Identifier,
		key LeafKey) ([]*Proof, error)

	// TODO(roasbeef): other stats stuff here, like total number of assets, etc
	//  * also eventually want pull/fetch stats, can be pulled out into another instance
}

// Registrar is an interface that allows a caller to register issuance of a new
// asset in a local/remote base universe instance.
type Registrar interface {
	// RegisterIssuance inserts a new minting leaf within the target
	// universe tree (based on the ID), stored at the base key.
	RegisterIssuance(ctx context.Context, id Identifier, key LeafKey,
		leaf *Leaf) (*Proof, error)
}

// IssuanceItem is an item that can be used to register a new issuance within a
// base universe.
type IssuanceItem struct {
	// ID is the identifier of the base universe that the item should be
	// registered within.
	ID Identifier

	// Key is the base key that the leaf is or will be stored at.
	Key LeafKey

	// Leaf is the minting leaf that was created.
	Leaf *Leaf

	// MetaReveal is the meta reveal that was created.
	MetaReveal *proof.MetaReveal
}

// BatchRegistrar is an interface that allows a caller to register a batch of
// issuance items within a base universe.
type BatchRegistrar interface {
	Registrar

	// RegisterNewIssuanceBatch inserts a batch of new minting leaves within
	// the target universe tree (based on the ID), stored at the base
	// key(s). We assume the proofs within the batch have already been
	// checked that they don't yet exist in the local database.
	RegisterNewIssuanceBatch(ctx context.Context,
		items []*IssuanceItem) error
}

const (
	// DefaultUniverseRPCPort is the default port that the universe RPC is
	// hosted on.
	DefaultUniverseRPCPort = 10029
)

// resolveUniverseAddr maps an RPC universe host (of the form 'host' or
// 'host:port') into a net.Addr.
func resolverUniverseAddr(uniAddr string) (net.Addr, error) {
	var (
		host string
		port int
	)

	if len(uniAddr) == 0 {
		return nil, fmt.Errorf("universe host cannot be empty")
	}

	// Split the address into its host and port components.
	h, p, err := net.SplitHostPort(uniAddr)
	if err != nil {
		// If a port wasn't specified, we'll assume the address only
		// contains the host so we'll use the default port.
		host = uniAddr
		port = DefaultUniverseRPCPort
	} else {
		// Otherwise, we'll note both the host and ports.
		host = h
		portNum, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		port = portNum
	}

	// TODO(roasbeef): add tor support

	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	return net.ResolveTCPAddr("tcp", hostPort)
}

// ServerAddr wraps the reachable network address of a remote universe
// server.
type ServerAddr struct {
	// ID is the unique identifier of the remote universe.
	ID int64

	// addrStr is the pure string version of the address before any name
	// resolution has taken place.
	addrStr string

	// addr is the resolved network address of the remote universe. This is
	// cached the first time so resolution doesn't need to be hit
	// repeatedly.
	addr net.Addr
}

// NewServerAddrFromStr creates a new server address from a string that is the
// host name of the remote universe server.
func NewServerAddrFromStr(s string) ServerAddr {
	return ServerAddr{
		addrStr: s,
	}
}

// NewServerAddr creates a new server address from both the universe addr ID
// and the host name string.
func NewServerAddr(i int64, s string) ServerAddr {
	return ServerAddr{
		ID:      i,
		addrStr: s,
	}
}

// Addr returns the net.addr the universe is hosted at.
func (s *ServerAddr) Addr() (net.Addr, error) {
	if s.addr != nil {
		return s.addr, nil
	}

	addr, err := resolverUniverseAddr(s.addrStr)
	if err != nil {
		return nil, err
	}

	s.addr = addr
	return addr, err
}

// HostStr returns the host string of the remote universe server.
func (s *ServerAddr) HostStr() string {
	return s.addrStr
}

// SyncType is an enum that describes the type of sync that should be performed
// between a local and remote universe.
type SyncType uint8

const (
	// SyncIssuance is a sync that will only sync new asset issuance events.
	SyncIssuance SyncType = iota

	// SyncFull is a sync that will sync all the assets in the universe.
	SyncFull
)

// String returns a human-readable string representation of the sync type.
func (s SyncType) String() string {
	switch s {
	case SyncIssuance:
		return "issuance"
	case SyncFull:
		return "full"
	default:
		return fmt.Sprintf("unknown(%v)", int(s))
	}
}

// AssetSyncDiff is the result of a success Universe sync. The diff contains the
// Universe root, and the set of assets that were added to the Universe.
type AssetSyncDiff struct {
	// OldUniverseRoot is the root of the universe before the sync.
	OldUniverseRoot BaseRoot

	// NewUniverseRoot is the new root of the Universe after the sync.
	NewUniverseRoot BaseRoot

	// NewAssetLeaves is the set of new leaf proofs that were added to the
	// Universe.
	NewLeafProofs []*Leaf

	// TODO(roasbeef): ability to return if things failed?
	//  * can used a sealed interface to return the error
}

// Syncer is used to synchronize the state of two Universe instances: a local
// instance and a remote instance. As a Universe is a tree based structure,
// tree based bisection can be used to find the point of divergence with
// syncing happening once that's found.
type Syncer interface {
	// SyncUniverse attempts to synchronize the local universe with the
	// remote universe, governed by the sync type and the set of universe
	// IDs to sync.
	SyncUniverse(ctx context.Context, host ServerAddr,
		syncType SyncType,
		idsToSync ...Identifier) ([]AssetSyncDiff, error)
}

// DiffEngine is a Universe diff engine that can be used to compare the state
// of two universes and find the set of assets that are different between them.
type DiffEngine interface {
	// RootNode returns the root node for a given base universe.
	RootNode(ctx context.Context, id Identifier) (BaseRoot, error)

	// RootNodes returns the set of root nodes for all known universes.
	RootNodes(ctx context.Context) ([]BaseRoot, error)

	// UniverseLeafKeys returns all the keys inserted in the universe.
	UniverseLeafKeys(ctx context.Context, id Identifier) ([]LeafKey, error)

	// FetchIssuanceProof attempts to fetch an issuance proof for the
	// target base leaf based on the universe identifier (assetID/groupKey).
	//
	// TODO(roasbeef): actually add this somewhere else?  * rn kinda
	// asymmetric, as just need this to complete final portion
	// of diff
	FetchIssuanceProof(ctx context.Context, id Identifier,
		key LeafKey) ([]*Proof, error)
}

// Commitment is an on chain universe commitment. This includes the merkle
// proof for a transaction which anchors the target universe root.
type Commitment struct {
	// BlockHeight is the height of the block that the commitment is
	// contained within.
	BlockHeight uint32

	// BlockHeader is the block header that commits to the transaction.
	BlockHeader wire.BlockHeader

	// MerkleProof is a merkle proof for the above transaction that the
	// anchor output was included.
	MerkleProof *proof.TxMerkleProof

	// UniverseRoot is the full Universe root for this commitment.
	UniverseRoot mssmt.Node
}

// CommittedIssuanceProof couples together a Bitcoin level merkle proof
// commitment with an issuance proof. This allows remote callers to verify that
// their responses re actually committed to within the chain.
type CommittedIssuanceProof struct {
	// ChainProof is the on chain proof that shows the Universe root has
	// been stamped in the chain.
	ChainProof *Commitment

	// TaprootAssetProof is a proof of new asset issuance.
	TaprootAssetProof *Proof
}

// ChainCommitter is used to commit a Universe backend in the chain.
type ChainCommitter interface {
	// CommitUniverse takes a Universe and returns a new commitment to that
	// Universe in the main chain.
	CommitUniverse(universe BaseBackend) (*Commitment, error)
}

// Canonical is an interface that allows a caller to query for the latest
// canonical Universe information related to an asset.
//
// TODO(roasbeef): sync methods too, divide into read/write?
type Canonical interface {
	BaseBackend

	// Query returns a fully proved response for the target base key.
	Query(context.Context, LeafKey) (*CommittedIssuanceProof, error)

	// LatestCommitment returns the latest chain commitment.
	LatestCommitment() (*Commitment, error)

	// UpdateChainCommitment takes in a series of chain commitments and
	// updates the commitment on chain.
	UpdateChainCommitment(chainCommits ...ChainCommitter) (*Commitment, error)
}

// FederationLog is used to keep track of the set Universe servers that
// comprise our current federation. This'll be used by the AutoSyncer to
// periodically push and sync new proof events against the federation.
type FederationLog interface {
	// UniverseServers returns the set of servers in the federation.
	UniverseServers(ctx context.Context) ([]ServerAddr, error)

	// AddServers adds a slice of servers to the federation.
	AddServers(ctx context.Context, addrs ...ServerAddr) error

	// RemoveServers removes a set of servers from the federation.
	RemoveServers(ctx context.Context, addrs ...ServerAddr) error

	// LogNewSyncs logs a new sync event for each server. This can be used
	// to keep track of the last time we synced with a remote server.
	LogNewSyncs(ctx context.Context, addrs ...ServerAddr) error
}

// ProofType is an enum that describes the type of proof which can be stored in
// a given universe.
type ProofType uint8

const (
	// ProofTypeUnspecified signifies an unspecified proof type.
	ProofTypeUnspecified ProofType = iota

	// ProofTypeIssuance corresponds to the issuance proof type.
	ProofTypeIssuance

	// ProofTypeTransfer corresponds to the transfer proof type.
	ProofTypeTransfer
)

// NewProofTypeFromAssetProof returns the proof type for the given asset proof.
func NewProofTypeFromAssetProof(proof *proof.Proof) (ProofType, error) {
	if proof == nil {
		return 0, fmt.Errorf("proof is nil")
	}

	if proof.Asset.IsGenesisAsset() {
		return ProofTypeIssuance, nil
	}

	return ProofTypeTransfer, nil
}

// String returns a human-readable string representation of the proof type.
func (t ProofType) String() string {
	switch t {
	case ProofTypeUnspecified:
		return "unspecified"
	case ProofTypeIssuance:
		return "issuance"
	case ProofTypeTransfer:
		return "transfer"
	}

	return fmt.Sprintf("unknown(%v)", int(t))
}

// NewProofTypeFromString returns the proof type corresponding to the given
// string.
func NewProofTypeFromString(typeStr string) (ProofType, error) {
	switch typeStr {
	case "unspecified":
		return ProofTypeUnspecified, nil
	case "issuance":
		return ProofTypeIssuance, nil
	case "transfer":
		return ProofTypeTransfer, nil
	default:
		return ProofTypeUnspecified, fmt.Errorf("unknown proof "+
			"type: %v", typeStr)
	}
}

// SyncStatsSort is an enum used to specify the sort order of the returned sync
// stats.
type SyncStatsSort uint8

const (
	// SortByNone is a sentinel value that indicates that no sorting should
	// be done.
	SortByNone SyncStatsSort = iota

	// SortByAssetName sorts the returned stats by the asset name.
	SortByAssetName

	// SortByAssetType sorts the returned stats by the asset type.
	SortByAssetType

	// SortByAssetID sorts the returned stats by the asset ID.
	SortByAssetID

	// SortByTotalSyncs sorts the returned stats by the total number of
	// syncs.
	SortByTotalSyncs

	// SortByTotalProofs sorts the returned stats by the total number of
	// proofs.
	SortByTotalProofs

	// SortByGenesisHeight sorts the returned stats by the genesis height.
	SortByGenesisHeight

	// SortByTotalSupply sorts the returned stats by the total supply.
	SortByTotalSupply
)

// SortDirection is an enum used to specify the sort direction of the returned.
type SortDirection uint8

const (
	// SortAscending is a sentinel value that indicates that the sort
	// should be in ascending order.
	SortAscending SortDirection = iota

	// SortDescending is a sentinel value that indicates that the sort
	// should be in descending order.
	SortDescending
)

// SyncStatsQuery packages a set of query parameters to retrieve stats related
// to the sync activity of a given Universe. Any of the filters can be
// specified, however only a single sort by value should be specified. The
// offset and limit fields can be used to implement pagination.
type SyncStatsQuery struct {
	// AssetNameFilter can be used to filter for stats for a given asset name.
	AssetNameFilter string

	// AssetIDFilter can be used to filter for stats for a given asset ID.
	AssetIDFilter asset.ID

	// AssetTypeFilter can be used to filter for stats for a given asset
	// type.
	AssetTypeFilter *asset.Type

	// SortBy is the sort order to use when returning the stats.
	SortBy SyncStatsSort

	// SortDirection is the sort direction to use when returning the stats.
	SortDirection SortDirection

	// Offset is the offset to use when returning the stats. This can be
	// used to paginate the response.
	Offset int

	// Limit is the maximum number of stats to return. This can be used to
	// paginate the response.
	Limit int
}

// AssetSyncSnapshot is a snapshot of the sync activity for a given asset.
type AssetSyncSnapshot struct {
	// AssetID is the ID of the asset.
	AssetID asset.ID

	// GroupKey is the optional group key of the asset.
	GroupKey *btcec.PublicKey

	// GenesisPoint is the first previous output that created the asset.
	GenesisPoint wire.OutPoint

	// AssetName is the name of the asset.
	AssetName string

	// AssetType is the type of the asset.
	AssetType asset.Type

	// TotalSupply is the total supply of the asset.
	TotalSupply uint64

	// GenesisHeight is the height of the block that the asset was created
	// in.
	GenesisHeight uint32

	// TotalSyncs is the total number of syncs that have been performed for
	// the target asset.
	TotalSyncs uint64

	// TotalProofs is the total number of proofs that have been inserted
	// for the asset.
	TotalProofs uint64

	// TODO(roasbeef): add last sync?
}

// AssetSyncStats is the response to a SyncStatsQuery request. It contains the
// original query, and the set of sync stats generated by the query.
type AssetSyncStats struct {
	// Query is the original query that was used to generate the stats.
	Query SyncStatsQuery

	// SyncStats is the set of sync stats generated by the query.
	SyncStats []AssetSyncSnapshot
}

// AggregateStats is a set of aggregate stats for a given Universe.
type AggregateStats struct {
	// NumTotalAssets is the total number of assets in the Universe.
	NumTotalAssets uint64

	// NumTotalSyncs is the total number of syncs that have been performed
	// in the Universe.
	NumTotalSyncs uint64

	// NumTotalProofs is the total number of proofs that have been inserted
	// into the Universe.
	NumTotalProofs uint64
}

// GroupedStatsQuery packages a set of query parameters to retrieve event based
// stats.
type GroupedStatsQuery struct {
	// StartTime is the start time to use when querying for stats.
	StartTime time.Time

	// EndTime is the end time to use when querying for stats.
	EndTime time.Time
}

// GroupedStats is a type for aggregated stats grouped by day.
type GroupedStats struct {
	AggregateStats

	// Date is the string formatted date (YYYY-MM-DD) that the stats are
	// for.
	Date string
}

// Telemetry it a type used by the Universe syncer and base universe to export
// telemetry information about the sync process. This logs events of new
// proofs, and also sync events for entire asset trees.
//
// TODO(roasbeef): prob want to add a wrapper around multiple instances, eg: to
// the main db and also prometheus or w/e
type Telemetry interface {
	// AggregateSyncStats returns stats aggregated over all assets within
	// the Universe.
	AggregateSyncStats(ctx context.Context) (AggregateStats, error)

	// LogSyncEvent logs a sync event for the target universe.
	//
	// TODO(roasbeef): log based on a given leaf, or entire tree?
	//  * rn main entrypoint is in RPC server, which is leaf based
	//  * alternatively, can log when a set of leaves are queried, as
	//    that's still a sync event, but can be a noop
	LogSyncEvent(ctx context.Context, uniID Identifier,
		key LeafKey) error

	// LogSyncEvents logs sync events for the target universe.
	LogSyncEvents(ctx context.Context, uniIDs ...Identifier) error

	// LogNewProofEvent logs a new proof insertion event for the target
	// universe.
	LogNewProofEvent(ctx context.Context, uniID Identifier,
		key LeafKey) error

	// LogNewProofEvents logs new proof insertion events for the target
	// universe.
	LogNewProofEvents(ctx context.Context, uniIDs ...Identifier) error

	// QuerySyncStats attempts to query the stats for the target universe.
	// For a given asset ID, tag, or type, the set of universe stats is
	// returned which lists information such as the total number of syncs
	// and known proofs for a given Universe server instance.
	QuerySyncStats(ctx context.Context,
		q SyncStatsQuery) (*AssetSyncStats, error)

	// QueryAssetStatsPerDay returns the stats for all assets grouped by
	// day.
	QueryAssetStatsPerDay(ctx context.Context,
		q GroupedStatsQuery) ([]*GroupedStats, error)
}
