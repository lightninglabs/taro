// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.21.0
// source: universe.sql

package sqlc

import (
	"context"
	"database/sql"
	"time"
)

const deleteUniverseEvents = `-- name: DeleteUniverseEvents :exec
WITH root_id AS (
    SELECT id
    FROM universe_roots
    WHERE namespace_root = $1
)
DELETE FROM universe_events
WHERE universe_root_id = (SELECT id from root_id)
`

func (q *Queries) DeleteUniverseEvents(ctx context.Context, namespaceRoot string) error {
	_, err := q.db.ExecContext(ctx, deleteUniverseEvents, namespaceRoot)
	return err
}

const deleteUniverseLeaves = `-- name: DeleteUniverseLeaves :exec
DELETE FROM universe_leaves
WHERE leaf_node_namespace = $1
`

func (q *Queries) DeleteUniverseLeaves(ctx context.Context, namespace string) error {
	_, err := q.db.ExecContext(ctx, deleteUniverseLeaves, namespace)
	return err
}

const deleteUniverseRoot = `-- name: DeleteUniverseRoot :exec
DELETE FROM universe_roots
WHERE namespace_root = $1
`

func (q *Queries) DeleteUniverseRoot(ctx context.Context, namespaceRoot string) error {
	_, err := q.db.ExecContext(ctx, deleteUniverseRoot, namespaceRoot)
	return err
}

const deleteUniverseServer = `-- name: DeleteUniverseServer :exec
DELETE FROM universe_servers
WHERE server_host = $1 OR id = $2
`

type DeleteUniverseServerParams struct {
	TargetServer string
	TargetID     int64
}

func (q *Queries) DeleteUniverseServer(ctx context.Context, arg DeleteUniverseServerParams) error {
	_, err := q.db.ExecContext(ctx, deleteUniverseServer, arg.TargetServer, arg.TargetID)
	return err
}

const fetchUniverseKeys = `-- name: FetchUniverseKeys :many
SELECT leaves.minting_point, leaves.script_key_bytes
FROM universe_leaves leaves
WHERE leaves.leaf_node_namespace = $1
`

type FetchUniverseKeysRow struct {
	MintingPoint   []byte
	ScriptKeyBytes []byte
}

func (q *Queries) FetchUniverseKeys(ctx context.Context, namespace string) ([]FetchUniverseKeysRow, error) {
	rows, err := q.db.QueryContext(ctx, fetchUniverseKeys, namespace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FetchUniverseKeysRow
	for rows.Next() {
		var i FetchUniverseKeysRow
		if err := rows.Scan(&i.MintingPoint, &i.ScriptKeyBytes); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const fetchUniverseRoot = `-- name: FetchUniverseRoot :one
SELECT universe_roots.asset_id, group_key, proof_type,
       mssmt_nodes.hash_key root_hash, mssmt_nodes.sum root_sum,
       genesis_assets.asset_tag asset_name
FROM universe_roots
JOIN mssmt_roots 
    ON universe_roots.namespace_root = mssmt_roots.namespace
JOIN mssmt_nodes 
    ON mssmt_nodes.hash_key = mssmt_roots.root_hash AND
       mssmt_nodes.namespace = mssmt_roots.namespace
JOIN genesis_assets
     ON genesis_assets.asset_id = universe_roots.asset_id
WHERE mssmt_nodes.namespace = $1
`

type FetchUniverseRootRow struct {
	AssetID   []byte
	GroupKey  []byte
	ProofType string
	RootHash  []byte
	RootSum   int64
	AssetName string
}

func (q *Queries) FetchUniverseRoot(ctx context.Context, namespace string) (FetchUniverseRootRow, error) {
	row := q.db.QueryRowContext(ctx, fetchUniverseRoot, namespace)
	var i FetchUniverseRootRow
	err := row.Scan(
		&i.AssetID,
		&i.GroupKey,
		&i.ProofType,
		&i.RootHash,
		&i.RootSum,
		&i.AssetName,
	)
	return i, err
}

const insertNewProofEvent = `-- name: InsertNewProofEvent :exec
WITH group_key_root_id AS (
    SELECT id
    FROM universe_roots
    WHERE group_key = $1
), asset_id_root_id AS (
    SELECT leaves.universe_root_id AS id
    FROM universe_leaves leaves
             JOIN genesis_info_view gen
                  ON leaves.asset_genesis_id = gen.gen_asset_id
    WHERE gen.asset_id = $4
    LIMIT 1
)
INSERT INTO universe_events (
    event_type, universe_root_id, event_time, event_timestamp
) VALUES (
    'NEW_PROOF',
        CASE WHEN length($1) > 0 THEN (
            SELECT id FROM group_key_root_id
        ) ELSE (
            SELECT id FROM asset_id_root_id
        ) END,
    $2, $3
)
`

type InsertNewProofEventParams struct {
	GroupKeyXOnly  interface{}
	EventTime      time.Time
	EventTimestamp int64
	AssetID        []byte
}

func (q *Queries) InsertNewProofEvent(ctx context.Context, arg InsertNewProofEventParams) error {
	_, err := q.db.ExecContext(ctx, insertNewProofEvent,
		arg.GroupKeyXOnly,
		arg.EventTime,
		arg.EventTimestamp,
		arg.AssetID,
	)
	return err
}

const insertNewSyncEvent = `-- name: InsertNewSyncEvent :exec
WITH group_key_root_id AS (
    SELECT id
    FROM universe_roots
    WHERE group_key = $1
), asset_id_root_id AS (
    SELECT leaves.universe_root_id AS id
    FROM universe_leaves leaves
    JOIN genesis_info_view gen
        ON leaves.asset_genesis_id = gen.gen_asset_id
    WHERE gen.asset_id = $4 
    LIMIT 1
)
INSERT INTO universe_events (
    event_type, universe_root_id, event_time, event_timestamp
) VALUES (
    'SYNC',
        CASE WHEN length($1) > 0 THEN (
            SELECT id FROM group_key_root_id
        ) ELSE (
            SELECT id FROM asset_id_root_id
        ) END,
    $2, $3
)
`

type InsertNewSyncEventParams struct {
	GroupKeyXOnly  interface{}
	EventTime      time.Time
	EventTimestamp int64
	AssetID        []byte
}

func (q *Queries) InsertNewSyncEvent(ctx context.Context, arg InsertNewSyncEventParams) error {
	_, err := q.db.ExecContext(ctx, insertNewSyncEvent,
		arg.GroupKeyXOnly,
		arg.EventTime,
		arg.EventTimestamp,
		arg.AssetID,
	)
	return err
}

const insertUniverseServer = `-- name: InsertUniverseServer :exec
INSERT INTO universe_servers(
    server_host, last_sync_time
) VALUES (
    $1, $2
)
`

type InsertUniverseServerParams struct {
	ServerHost   string
	LastSyncTime time.Time
}

func (q *Queries) InsertUniverseServer(ctx context.Context, arg InsertUniverseServerParams) error {
	_, err := q.db.ExecContext(ctx, insertUniverseServer, arg.ServerHost, arg.LastSyncTime)
	return err
}

const listUniverseServers = `-- name: ListUniverseServers :many
SELECT id, server_host, last_sync_time FROM universe_servers
`

func (q *Queries) ListUniverseServers(ctx context.Context) ([]UniverseServer, error) {
	rows, err := q.db.QueryContext(ctx, listUniverseServers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []UniverseServer
	for rows.Next() {
		var i UniverseServer
		if err := rows.Scan(&i.ID, &i.ServerHost, &i.LastSyncTime); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const logServerSync = `-- name: LogServerSync :exec
UPDATE universe_servers
SET last_sync_time = $1
WHERE server_host = $2
`

type LogServerSyncParams struct {
	NewSyncTime  time.Time
	TargetServer string
}

func (q *Queries) LogServerSync(ctx context.Context, arg LogServerSyncParams) error {
	_, err := q.db.ExecContext(ctx, logServerSync, arg.NewSyncTime, arg.TargetServer)
	return err
}

const queryAssetStatsPerDayPostgres = `-- name: QueryAssetStatsPerDayPostgres :many
SELECT
    to_char(to_timestamp(event_timestamp), 'YYYY-MM-DD') AS day,
    SUM(CASE WHEN event_type = 'SYNC' THEN 1 ELSE 0 END) AS sync_events,
    SUM(CASE WHEN event_type = 'NEW_PROOF' THEN 1 ELSE 0 END) AS new_proof_events
FROM universe_events
WHERE event_type IN ('SYNC', 'NEW_PROOF') AND
      event_timestamp >= $1 AND event_timestamp <= $2
GROUP BY day
ORDER BY day
`

type QueryAssetStatsPerDayPostgresParams struct {
	StartTime int64
	EndTime   int64
}

type QueryAssetStatsPerDayPostgresRow struct {
	Day            string
	SyncEvents     int64
	NewProofEvents int64
}

func (q *Queries) QueryAssetStatsPerDayPostgres(ctx context.Context, arg QueryAssetStatsPerDayPostgresParams) ([]QueryAssetStatsPerDayPostgresRow, error) {
	rows, err := q.db.QueryContext(ctx, queryAssetStatsPerDayPostgres, arg.StartTime, arg.EndTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []QueryAssetStatsPerDayPostgresRow
	for rows.Next() {
		var i QueryAssetStatsPerDayPostgresRow
		if err := rows.Scan(&i.Day, &i.SyncEvents, &i.NewProofEvents); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const queryAssetStatsPerDaySqlite = `-- name: QueryAssetStatsPerDaySqlite :many
SELECT
    cast(strftime('%Y-%m-%d', datetime(event_timestamp, 'unixepoch')) as text) AS day,
    SUM(CASE WHEN event_type = 'SYNC' THEN 1 ELSE 0 END) AS sync_events,
    SUM(CASE WHEN event_type = 'NEW_PROOF' THEN 1 ELSE 0 END) AS new_proof_events
FROM universe_events
WHERE event_type IN ('SYNC', 'NEW_PROOF') AND
      event_timestamp >= $1 AND event_timestamp <= $2
GROUP BY day
ORDER BY day
`

type QueryAssetStatsPerDaySqliteParams struct {
	StartTime int64
	EndTime   int64
}

type QueryAssetStatsPerDaySqliteRow struct {
	Day            string
	SyncEvents     int64
	NewProofEvents int64
}

func (q *Queries) QueryAssetStatsPerDaySqlite(ctx context.Context, arg QueryAssetStatsPerDaySqliteParams) ([]QueryAssetStatsPerDaySqliteRow, error) {
	rows, err := q.db.QueryContext(ctx, queryAssetStatsPerDaySqlite, arg.StartTime, arg.EndTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []QueryAssetStatsPerDaySqliteRow
	for rows.Next() {
		var i QueryAssetStatsPerDaySqliteRow
		if err := rows.Scan(&i.Day, &i.SyncEvents, &i.NewProofEvents); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const queryFederationGlobalSyncConfigs = `-- name: QueryFederationGlobalSyncConfigs :many
SELECT proof_type, allow_sync_insert, allow_sync_export
FROM federation_global_sync_config
`

func (q *Queries) QueryFederationGlobalSyncConfigs(ctx context.Context) ([]FederationGlobalSyncConfig, error) {
	rows, err := q.db.QueryContext(ctx, queryFederationGlobalSyncConfigs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FederationGlobalSyncConfig
	for rows.Next() {
		var i FederationGlobalSyncConfig
		if err := rows.Scan(&i.ProofType, &i.AllowSyncInsert, &i.AllowSyncExport); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const queryFederationUniSyncConfigs = `-- name: QueryFederationUniSyncConfigs :many
SELECT asset_id, group_key, proof_type, allow_sync_insert, allow_sync_export
FROM federation_uni_sync_config
`

func (q *Queries) QueryFederationUniSyncConfigs(ctx context.Context) ([]FederationUniSyncConfig, error) {
	rows, err := q.db.QueryContext(ctx, queryFederationUniSyncConfigs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FederationUniSyncConfig
	for rows.Next() {
		var i FederationUniSyncConfig
		if err := rows.Scan(
			&i.AssetID,
			&i.GroupKey,
			&i.ProofType,
			&i.AllowSyncInsert,
			&i.AllowSyncExport,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const queryUniverseAssetStats = `-- name: QueryUniverseAssetStats :many

WITH asset_supply AS (
    SELECT SUM(nodes.sum) AS supply, gen.asset_id AS asset_id
    FROM universe_leaves leaves
    JOIN mssmt_nodes nodes
        ON leaves.leaf_node_key = nodes.key AND
           leaves.leaf_node_namespace = nodes.namespace
    JOIN genesis_info_view gen
        ON leaves.asset_genesis_id = gen.gen_asset_id
    GROUP BY gen.asset_id
), asset_info AS (
    SELECT asset_supply.supply, gen.asset_id AS asset_id, 
           gen.asset_tag AS asset_name, gen.asset_type AS asset_type,
           gen.block_height AS genesis_height, gen.prev_out AS genesis_prev_out,
           group_info.tweaked_group_key AS group_key
    FROM genesis_info_view gen
    JOIN asset_supply
        ON asset_supply.asset_id = gen.asset_id
    -- We use a LEFT JOIN here as not every asset has a group key, so this'll
    -- generate rows that have NULL values for the group key fields if an asset
    -- doesn't have a group key.
    LEFT JOIN key_group_info_view group_info
        ON gen.gen_asset_id = group_info.gen_asset_id
    WHERE (gen.asset_tag = $5 OR $5 IS NULL) AND
          (gen.asset_type = $6 OR $6 IS NULL) AND
          (gen.asset_id = $7 OR $7 IS NULL)
)
SELECT asset_info.supply AS asset_supply, asset_info.asset_name AS asset_name,
    asset_info.asset_type AS asset_type, asset_info.asset_id AS asset_id,
    asset_info.genesis_height AS genesis_height,
    asset_info.genesis_prev_out AS genesis_prev_out,
    asset_info.group_key AS group_key,
    universe_stats.total_asset_syncs AS total_syncs,
    universe_stats.total_asset_proofs AS total_proofs
FROM asset_info
JOIN universe_stats
    ON asset_info.asset_id = universe_stats.asset_id
ORDER BY
    CASE WHEN $1 = 'asset_id' AND $2 = 0 THEN
             asset_info.asset_id END ASC,
    CASE WHEN $1 = 'asset_id' AND $2 = 1 THEN
             asset_info.asset_id END DESC,
    CASE WHEN $1 = 'asset_name' AND $2 = 0 THEN
             asset_info.asset_name END ASC ,
    CASE WHEN $1 = 'asset_name' AND $2 = 1 THEN
             asset_info.asset_name END DESC ,
    CASE WHEN $1 = 'asset_type' AND $2 = 0 THEN
             asset_info.asset_type END ASC ,
    CASE WHEN $1 = 'asset_type' AND $2 = 1 THEN
             asset_info.asset_type END DESC,
    CASE WHEN $1 = 'total_syncs' AND $2 = 0 THEN
             universe_stats.total_asset_syncs END ASC ,
    CASE WHEN $1 = 'total_syncs' AND $2 = 1 THEN
             universe_stats.total_asset_syncs END DESC,
    CASE WHEN $1 = 'total_proofs' AND $2 = 0 THEN
             universe_stats.total_asset_proofs END ASC ,
    CASE WHEN $1 = 'total_proofs' AND $2 = 1 THEN
             universe_stats.total_asset_proofs END DESC,
    CASE WHEN $1 = 'genesis_height' AND $2 = 0 THEN
             asset_info.genesis_height END ASC ,
    CASE WHEN $1 = 'genesis_height' AND $2 = 1 THEN
             asset_info.genesis_height END DESC,
    CASE WHEN $1 = 'total_supply' AND $2 = 0 THEN
             asset_info.supply END ASC ,
    CASE WHEN $1 = 'total_supply' AND $2 = 1 THEN
             asset_info.supply END DESC
LIMIT $4 OFFSET $3
`

type QueryUniverseAssetStatsParams struct {
	SortBy        interface{}
	SortDirection interface{}
	NumOffset     int32
	NumLimit      int32
	AssetName     sql.NullString
	AssetType     sql.NullInt16
	AssetID       []byte
}

type QueryUniverseAssetStatsRow struct {
	AssetSupply    int64
	AssetName      string
	AssetType      int16
	AssetID        []byte
	GenesisHeight  sql.NullInt32
	GenesisPrevOut []byte
	GroupKey       []byte
	TotalSyncs     int64
	TotalProofs    int64
}

// TODO(roasbeef): use the universe id instead for the grouping? so namespace
// root, simplifies queries
func (q *Queries) QueryUniverseAssetStats(ctx context.Context, arg QueryUniverseAssetStatsParams) ([]QueryUniverseAssetStatsRow, error) {
	rows, err := q.db.QueryContext(ctx, queryUniverseAssetStats,
		arg.SortBy,
		arg.SortDirection,
		arg.NumOffset,
		arg.NumLimit,
		arg.AssetName,
		arg.AssetType,
		arg.AssetID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []QueryUniverseAssetStatsRow
	for rows.Next() {
		var i QueryUniverseAssetStatsRow
		if err := rows.Scan(
			&i.AssetSupply,
			&i.AssetName,
			&i.AssetType,
			&i.AssetID,
			&i.GenesisHeight,
			&i.GenesisPrevOut,
			&i.GroupKey,
			&i.TotalSyncs,
			&i.TotalProofs,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const queryUniverseLeaves = `-- name: QueryUniverseLeaves :many
SELECT leaves.script_key_bytes, gen.gen_asset_id, nodes.value genesis_proof, 
       nodes.sum sum_amt, gen.asset_id
FROM universe_leaves leaves
JOIN mssmt_nodes nodes
    ON leaves.leaf_node_key = nodes.key AND
        leaves.leaf_node_namespace = nodes.namespace
JOIN genesis_info_view gen
    ON leaves.asset_genesis_id = gen.gen_asset_id
WHERE leaves.leaf_node_namespace = $1 
        AND 
    (leaves.minting_point = $2 OR 
        $2 IS NULL) 
        AND
    (leaves.script_key_bytes = $3 OR 
        $3 IS NULL)
`

type QueryUniverseLeavesParams struct {
	Namespace         string
	MintingPointBytes []byte
	ScriptKeyBytes    []byte
}

type QueryUniverseLeavesRow struct {
	ScriptKeyBytes []byte
	GenAssetID     int64
	GenesisProof   []byte
	SumAmt         int64
	AssetID        []byte
}

func (q *Queries) QueryUniverseLeaves(ctx context.Context, arg QueryUniverseLeavesParams) ([]QueryUniverseLeavesRow, error) {
	rows, err := q.db.QueryContext(ctx, queryUniverseLeaves, arg.Namespace, arg.MintingPointBytes, arg.ScriptKeyBytes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []QueryUniverseLeavesRow
	for rows.Next() {
		var i QueryUniverseLeavesRow
		if err := rows.Scan(
			&i.ScriptKeyBytes,
			&i.GenAssetID,
			&i.GenesisProof,
			&i.SumAmt,
			&i.AssetID,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const queryUniverseStats = `-- name: QueryUniverseStats :one
WITH num_assets As (
    SELECT COUNT(*) AS num_assets
    FROM universe_roots
)
SELECT COALESCE(SUM(universe_stats.total_asset_syncs), 0) AS total_syncs,
       COALESCE(SUM(universe_stats.total_asset_proofs), 0) AS total_proofs,
       COUNT(num_assets) AS total_num_assets
FROM universe_stats, num_assets
`

type QueryUniverseStatsRow struct {
	TotalSyncs     interface{}
	TotalProofs    interface{}
	TotalNumAssets int64
}

func (q *Queries) QueryUniverseStats(ctx context.Context) (QueryUniverseStatsRow, error) {
	row := q.db.QueryRowContext(ctx, queryUniverseStats)
	var i QueryUniverseStatsRow
	err := row.Scan(&i.TotalSyncs, &i.TotalProofs, &i.TotalNumAssets)
	return i, err
}

const universeLeaves = `-- name: UniverseLeaves :many
SELECT id, asset_genesis_id, minting_point, script_key_bytes, universe_root_id, leaf_node_key, leaf_node_namespace FROM universe_leaves
`

func (q *Queries) UniverseLeaves(ctx context.Context) ([]UniverseLeafe, error) {
	rows, err := q.db.QueryContext(ctx, universeLeaves)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []UniverseLeafe
	for rows.Next() {
		var i UniverseLeafe
		if err := rows.Scan(
			&i.ID,
			&i.AssetGenesisID,
			&i.MintingPoint,
			&i.ScriptKeyBytes,
			&i.UniverseRootID,
			&i.LeafNodeKey,
			&i.LeafNodeNamespace,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const universeRoots = `-- name: UniverseRoots :many
SELECT universe_roots.asset_id, group_key, proof_type,
       mssmt_roots.root_hash root_hash, mssmt_nodes.sum root_sum,
       genesis_assets.asset_tag asset_name
FROM universe_roots
JOIN mssmt_roots
    ON universe_roots.namespace_root = mssmt_roots.namespace
JOIN mssmt_nodes
    ON mssmt_nodes.hash_key = mssmt_roots.root_hash AND
       mssmt_nodes.namespace = mssmt_roots.namespace
JOIN genesis_assets
    ON genesis_assets.asset_id = universe_roots.asset_id
`

type UniverseRootsRow struct {
	AssetID   []byte
	GroupKey  []byte
	ProofType string
	RootHash  []byte
	RootSum   int64
	AssetName string
}

func (q *Queries) UniverseRoots(ctx context.Context) ([]UniverseRootsRow, error) {
	rows, err := q.db.QueryContext(ctx, universeRoots)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []UniverseRootsRow
	for rows.Next() {
		var i UniverseRootsRow
		if err := rows.Scan(
			&i.AssetID,
			&i.GroupKey,
			&i.ProofType,
			&i.RootHash,
			&i.RootSum,
			&i.AssetName,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const upsertFederationGlobalSyncConfig = `-- name: UpsertFederationGlobalSyncConfig :exec
INSERT INTO federation_global_sync_config (
    proof_type, allow_sync_insert, allow_sync_export
)
VALUES ($1, $2, $3)
ON CONFLICT(proof_type)
    DO UPDATE SET
    allow_sync_insert = $2,
    allow_sync_export = $3
`

type UpsertFederationGlobalSyncConfigParams struct {
	ProofType       string
	AllowSyncInsert bool
	AllowSyncExport bool
}

func (q *Queries) UpsertFederationGlobalSyncConfig(ctx context.Context, arg UpsertFederationGlobalSyncConfigParams) error {
	_, err := q.db.ExecContext(ctx, upsertFederationGlobalSyncConfig, arg.ProofType, arg.AllowSyncInsert, arg.AllowSyncExport)
	return err
}

const upsertFederationUniSyncConfig = `-- name: UpsertFederationUniSyncConfig :exec
INSERT INTO federation_uni_sync_config  (
    asset_id, group_key, proof_type, allow_sync_insert, allow_sync_export
)
VALUES(
    $1, $2, $3, $4, $5
)
ON CONFLICT(asset_id, group_key, proof_type)
    DO UPDATE SET
    allow_sync_insert = $4,
    allow_sync_export = $5
`

type UpsertFederationUniSyncConfigParams struct {
	AssetID         []byte
	GroupKey        []byte
	ProofType       string
	AllowSyncInsert bool
	AllowSyncExport bool
}

func (q *Queries) UpsertFederationUniSyncConfig(ctx context.Context, arg UpsertFederationUniSyncConfigParams) error {
	_, err := q.db.ExecContext(ctx, upsertFederationUniSyncConfig,
		arg.AssetID,
		arg.GroupKey,
		arg.ProofType,
		arg.AllowSyncInsert,
		arg.AllowSyncExport,
	)
	return err
}

const upsertUniverseLeaf = `-- name: UpsertUniverseLeaf :exec
INSERT INTO universe_leaves (
    asset_genesis_id, script_key_bytes, universe_root_id, leaf_node_key, 
    leaf_node_namespace, minting_point
) VALUES (
    $1, $2, $3, $4,
    $5, $6
) ON CONFLICT (minting_point, script_key_bytes)
    -- This is a NOP, minting_point and script_key_bytes are the unique fields
    -- that caused the conflict.
    DO UPDATE SET minting_point = EXCLUDED.minting_point,
                  script_key_bytes = EXCLUDED.script_key_bytes
`

type UpsertUniverseLeafParams struct {
	AssetGenesisID    int64
	ScriptKeyBytes    []byte
	UniverseRootID    int64
	LeafNodeKey       []byte
	LeafNodeNamespace string
	MintingPoint      []byte
}

func (q *Queries) UpsertUniverseLeaf(ctx context.Context, arg UpsertUniverseLeafParams) error {
	_, err := q.db.ExecContext(ctx, upsertUniverseLeaf,
		arg.AssetGenesisID,
		arg.ScriptKeyBytes,
		arg.UniverseRootID,
		arg.LeafNodeKey,
		arg.LeafNodeNamespace,
		arg.MintingPoint,
	)
	return err
}

const upsertUniverseRoot = `-- name: UpsertUniverseRoot :one
INSERT INTO universe_roots (
    namespace_root, asset_id, group_key, proof_type
) VALUES (
    $1, $2, $3, $4
) ON CONFLICT (namespace_root)
    -- This is a NOP, namespace_root is the unique field that caused the
    -- conflict.
    DO UPDATE SET namespace_root = EXCLUDED.namespace_root
RETURNING id
`

type UpsertUniverseRootParams struct {
	NamespaceRoot string
	AssetID       []byte
	GroupKey      []byte
	ProofType     string
}

func (q *Queries) UpsertUniverseRoot(ctx context.Context, arg UpsertUniverseRootParams) (int64, error) {
	row := q.db.QueryRowContext(ctx, upsertUniverseRoot,
		arg.NamespaceRoot,
		arg.AssetID,
		arg.GroupKey,
		arg.ProofType,
	)
	var id int64
	err := row.Scan(&id)
	return id, err
}
