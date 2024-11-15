// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: addrs.sql

package sqlc

import (
	"context"
	"database/sql"
	"time"
)

const fetchAddrByTaprootOutputKey = `-- name: FetchAddrByTaprootOutputKey :one
SELECT
    version, asset_version, genesis_asset_id, group_key, tapscript_sibling,
    taproot_output_key, amount, asset_type, creation_time, managed_from,
    proof_courier_addr,
    script_keys.script_key_id, script_keys.internal_key_id, script_keys.tweaked_script_key, script_keys.tweak, script_keys.declared_known,
    raw_script_keys.key_id, raw_script_keys.raw_key, raw_script_keys.key_family, raw_script_keys.key_index,
    taproot_keys.raw_key AS raw_taproot_key,
    taproot_keys.key_family AS taproot_key_family,
    taproot_keys.key_index AS taproot_key_index
FROM addrs
JOIN script_keys
  ON addrs.script_key_id = script_keys.script_key_id
JOIN internal_keys raw_script_keys
  ON script_keys.internal_key_id = raw_script_keys.key_id
JOIN internal_keys taproot_keys
  ON addrs.taproot_key_id = taproot_keys.key_id
WHERE taproot_output_key = $1
`

type FetchAddrByTaprootOutputKeyRow struct {
	Version          int16
	AssetVersion     int16
	GenesisAssetID   int64
	GroupKey         []byte
	TapscriptSibling []byte
	TaprootOutputKey []byte
	Amount           int64
	AssetType        int16
	CreationTime     time.Time
	ManagedFrom      sql.NullTime
	ProofCourierAddr []byte
	ScriptKey        ScriptKey
	InternalKey      InternalKey
	RawTaprootKey    []byte
	TaprootKeyFamily int32
	TaprootKeyIndex  int32
}

func (q *Queries) FetchAddrByTaprootOutputKey(ctx context.Context, taprootOutputKey []byte) (FetchAddrByTaprootOutputKeyRow, error) {
	row := q.db.QueryRowContext(ctx, fetchAddrByTaprootOutputKey, taprootOutputKey)
	var i FetchAddrByTaprootOutputKeyRow
	err := row.Scan(
		&i.Version,
		&i.AssetVersion,
		&i.GenesisAssetID,
		&i.GroupKey,
		&i.TapscriptSibling,
		&i.TaprootOutputKey,
		&i.Amount,
		&i.AssetType,
		&i.CreationTime,
		&i.ManagedFrom,
		&i.ProofCourierAddr,
		&i.ScriptKey.ScriptKeyID,
		&i.ScriptKey.InternalKeyID,
		&i.ScriptKey.TweakedScriptKey,
		&i.ScriptKey.Tweak,
		&i.ScriptKey.DeclaredKnown,
		&i.InternalKey.KeyID,
		&i.InternalKey.RawKey,
		&i.InternalKey.KeyFamily,
		&i.InternalKey.KeyIndex,
		&i.RawTaprootKey,
		&i.TaprootKeyFamily,
		&i.TaprootKeyIndex,
	)
	return i, err
}

const fetchAddrEvent = `-- name: FetchAddrEvent :one
SELECT
    creation_time, status, asset_proof_id, asset_id,
    chain_txns.txid as txid,
    chain_txns.block_height as confirmation_height,
    chain_txn_output_index as output_index,
    managed_utxos.amt_sats as amt_sats,
    managed_utxos.tapscript_sibling as tapscript_sibling,
    internal_keys.raw_key as internal_key
FROM addr_events
LEFT JOIN chain_txns
       ON addr_events.chain_txn_id = chain_txns.txn_id
LEFT JOIN managed_utxos
       ON addr_events.managed_utxo_id = managed_utxos.utxo_id
LEFT JOIN internal_keys
       ON managed_utxos.internal_key_id = internal_keys.key_id
WHERE id = $1
`

type FetchAddrEventRow struct {
	CreationTime       time.Time
	Status             int16
	AssetProofID       sql.NullInt64
	AssetID            sql.NullInt64
	Txid               []byte
	ConfirmationHeight sql.NullInt32
	OutputIndex        int32
	AmtSats            sql.NullInt64
	TapscriptSibling   []byte
	InternalKey        []byte
}

func (q *Queries) FetchAddrEvent(ctx context.Context, id int64) (FetchAddrEventRow, error) {
	row := q.db.QueryRowContext(ctx, fetchAddrEvent, id)
	var i FetchAddrEventRow
	err := row.Scan(
		&i.CreationTime,
		&i.Status,
		&i.AssetProofID,
		&i.AssetID,
		&i.Txid,
		&i.ConfirmationHeight,
		&i.OutputIndex,
		&i.AmtSats,
		&i.TapscriptSibling,
		&i.InternalKey,
	)
	return i, err
}

const fetchAddrEventByAddrKeyAndOutpoint = `-- name: FetchAddrEventByAddrKeyAndOutpoint :one
WITH target_addr(addr_id) AS (
    SELECT id
    FROM addrs
    WHERE addrs.taproot_output_key = $1
)
SELECT
    addr_events.id, creation_time, status, asset_proof_id, asset_id,
    chain_txns.txid as txid,
    chain_txns.block_height as confirmation_height,
    chain_txn_output_index as output_index,
    managed_utxos.amt_sats as amt_sats,
    managed_utxos.tapscript_sibling as tapscript_sibling,
    internal_keys.raw_key as internal_key
FROM addr_events
JOIN target_addr
  ON addr_events.addr_id = target_addr.addr_id
LEFT JOIN chain_txns
       ON addr_events.chain_txn_id = chain_txns.txn_id
LEFT JOIN managed_utxos
       ON addr_events.managed_utxo_id = managed_utxos.utxo_id
LEFT JOIN internal_keys
       ON managed_utxos.internal_key_id = internal_keys.key_id
WHERE chain_txns.txid = $2
  AND chain_txn_output_index = $3
`

type FetchAddrEventByAddrKeyAndOutpointParams struct {
	TaprootOutputKey    []byte
	Txid                []byte
	ChainTxnOutputIndex int32
}

type FetchAddrEventByAddrKeyAndOutpointRow struct {
	ID                 int64
	CreationTime       time.Time
	Status             int16
	AssetProofID       sql.NullInt64
	AssetID            sql.NullInt64
	Txid               []byte
	ConfirmationHeight sql.NullInt32
	OutputIndex        int32
	AmtSats            sql.NullInt64
	TapscriptSibling   []byte
	InternalKey        []byte
}

func (q *Queries) FetchAddrEventByAddrKeyAndOutpoint(ctx context.Context, arg FetchAddrEventByAddrKeyAndOutpointParams) (FetchAddrEventByAddrKeyAndOutpointRow, error) {
	row := q.db.QueryRowContext(ctx, fetchAddrEventByAddrKeyAndOutpoint, arg.TaprootOutputKey, arg.Txid, arg.ChainTxnOutputIndex)
	var i FetchAddrEventByAddrKeyAndOutpointRow
	err := row.Scan(
		&i.ID,
		&i.CreationTime,
		&i.Status,
		&i.AssetProofID,
		&i.AssetID,
		&i.Txid,
		&i.ConfirmationHeight,
		&i.OutputIndex,
		&i.AmtSats,
		&i.TapscriptSibling,
		&i.InternalKey,
	)
	return i, err
}

const fetchAddrs = `-- name: FetchAddrs :many
SELECT 
    version, asset_version, genesis_asset_id, group_key, tapscript_sibling,
    taproot_output_key, amount, asset_type, creation_time, managed_from,
    proof_courier_addr,
    script_keys.script_key_id, script_keys.internal_key_id, script_keys.tweaked_script_key, script_keys.tweak, script_keys.declared_known,
    raw_script_keys.key_id, raw_script_keys.raw_key, raw_script_keys.key_family, raw_script_keys.key_index,
    taproot_keys.raw_key AS raw_taproot_key, 
    taproot_keys.key_family AS taproot_key_family,
    taproot_keys.key_index AS taproot_key_index
FROM addrs
JOIN script_keys
    ON addrs.script_key_id = script_keys.script_key_id
JOIN internal_keys raw_script_keys
    ON script_keys.internal_key_id = raw_script_keys.key_id
JOIN internal_keys taproot_keys
    ON addrs.taproot_key_id = taproot_keys.key_id
WHERE creation_time >= $1
    AND creation_time <= $2
    AND ($3 = false OR
         (CASE WHEN managed_from IS NULL THEN true ELSE false END) = $3)
ORDER BY addrs.creation_time
LIMIT $5 OFFSET $4
`

type FetchAddrsParams struct {
	CreatedAfter  time.Time
	CreatedBefore time.Time
	UnmanagedOnly interface{}
	NumOffset     int32
	NumLimit      int32
}

type FetchAddrsRow struct {
	Version          int16
	AssetVersion     int16
	GenesisAssetID   int64
	GroupKey         []byte
	TapscriptSibling []byte
	TaprootOutputKey []byte
	Amount           int64
	AssetType        int16
	CreationTime     time.Time
	ManagedFrom      sql.NullTime
	ProofCourierAddr []byte
	ScriptKey        ScriptKey
	InternalKey      InternalKey
	RawTaprootKey    []byte
	TaprootKeyFamily int32
	TaprootKeyIndex  int32
}

func (q *Queries) FetchAddrs(ctx context.Context, arg FetchAddrsParams) ([]FetchAddrsRow, error) {
	rows, err := q.db.QueryContext(ctx, fetchAddrs,
		arg.CreatedAfter,
		arg.CreatedBefore,
		arg.UnmanagedOnly,
		arg.NumOffset,
		arg.NumLimit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FetchAddrsRow
	for rows.Next() {
		var i FetchAddrsRow
		if err := rows.Scan(
			&i.Version,
			&i.AssetVersion,
			&i.GenesisAssetID,
			&i.GroupKey,
			&i.TapscriptSibling,
			&i.TaprootOutputKey,
			&i.Amount,
			&i.AssetType,
			&i.CreationTime,
			&i.ManagedFrom,
			&i.ProofCourierAddr,
			&i.ScriptKey.ScriptKeyID,
			&i.ScriptKey.InternalKeyID,
			&i.ScriptKey.TweakedScriptKey,
			&i.ScriptKey.Tweak,
			&i.ScriptKey.DeclaredKnown,
			&i.InternalKey.KeyID,
			&i.InternalKey.RawKey,
			&i.InternalKey.KeyFamily,
			&i.InternalKey.KeyIndex,
			&i.RawTaprootKey,
			&i.TaprootKeyFamily,
			&i.TaprootKeyIndex,
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

const insertAddr = `-- name: InsertAddr :one
INSERT INTO addrs (
    version, asset_version, genesis_asset_id, group_key, script_key_id,
    taproot_key_id, tapscript_sibling, taproot_output_key, amount, asset_type,
    creation_time, proof_courier_addr
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id
`

type InsertAddrParams struct {
	Version          int16
	AssetVersion     int16
	GenesisAssetID   int64
	GroupKey         []byte
	ScriptKeyID      int64
	TaprootKeyID     int64
	TapscriptSibling []byte
	TaprootOutputKey []byte
	Amount           int64
	AssetType        int16
	CreationTime     time.Time
	ProofCourierAddr []byte
}

func (q *Queries) InsertAddr(ctx context.Context, arg InsertAddrParams) (int64, error) {
	row := q.db.QueryRowContext(ctx, insertAddr,
		arg.Version,
		arg.AssetVersion,
		arg.GenesisAssetID,
		arg.GroupKey,
		arg.ScriptKeyID,
		arg.TaprootKeyID,
		arg.TapscriptSibling,
		arg.TaprootOutputKey,
		arg.Amount,
		arg.AssetType,
		arg.CreationTime,
		arg.ProofCourierAddr,
	)
	var id int64
	err := row.Scan(&id)
	return id, err
}

const queryEventIDs = `-- name: QueryEventIDs :many
SELECT
    addr_events.id as event_id, addrs.taproot_output_key as taproot_output_key
FROM addr_events
JOIN addrs
  ON addr_events.addr_id = addrs.id
WHERE addr_events.status >= $1 
  AND addr_events.status <= $2
  AND COALESCE($3, addrs.taproot_output_key) = addrs.taproot_output_key
  AND addr_events.creation_time >= $4
ORDER by addr_events.creation_time
`

type QueryEventIDsParams struct {
	StatusFrom     int16
	StatusTo       int16
	AddrTaprootKey []byte
	CreatedAfter   time.Time
}

type QueryEventIDsRow struct {
	EventID          int64
	TaprootOutputKey []byte
}

func (q *Queries) QueryEventIDs(ctx context.Context, arg QueryEventIDsParams) ([]QueryEventIDsRow, error) {
	rows, err := q.db.QueryContext(ctx, queryEventIDs,
		arg.StatusFrom,
		arg.StatusTo,
		arg.AddrTaprootKey,
		arg.CreatedAfter,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []QueryEventIDsRow
	for rows.Next() {
		var i QueryEventIDsRow
		if err := rows.Scan(&i.EventID, &i.TaprootOutputKey); err != nil {
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

const setAddrManaged = `-- name: SetAddrManaged :exec
WITH target_addr(addr_id) AS (
    SELECT id
    FROM addrs
    WHERE addrs.taproot_output_key = $1
)
UPDATE addrs
SET managed_from = $2
WHERE id = (SELECT addr_id FROM target_addr)
`

type SetAddrManagedParams struct {
	TaprootOutputKey []byte
	ManagedFrom      sql.NullTime
}

func (q *Queries) SetAddrManaged(ctx context.Context, arg SetAddrManagedParams) error {
	_, err := q.db.ExecContext(ctx, setAddrManaged, arg.TaprootOutputKey, arg.ManagedFrom)
	return err
}

const upsertAddrEvent = `-- name: UpsertAddrEvent :one
WITH target_addr(addr_id) AS (
    SELECT id
    FROM addrs
    WHERE addrs.taproot_output_key = $1
), target_chain_txn(txn_id) AS (
    SELECT txn_id
    FROM chain_txns
    WHERE chain_txns.txid = $2
)
INSERT INTO addr_events (
    creation_time, addr_id, status, chain_txn_id, chain_txn_output_index,
    managed_utxo_id, asset_proof_id, asset_id
) VALUES (
    $3, (SELECT addr_id FROM target_addr), $4,
    (SELECT txn_id FROM target_chain_txn), $5, $6, $7, $8
)
ON CONFLICT (addr_id, chain_txn_id, chain_txn_output_index)
    DO UPDATE SET status = EXCLUDED.status,
                  asset_proof_id = COALESCE(EXCLUDED.asset_proof_id, addr_events.asset_proof_id),
                  asset_id = COALESCE(EXCLUDED.asset_id, addr_events.asset_id)
RETURNING id
`

type UpsertAddrEventParams struct {
	TaprootOutputKey    []byte
	Txid                []byte
	CreationTime        time.Time
	Status              int16
	ChainTxnOutputIndex int32
	ManagedUtxoID       int64
	AssetProofID        sql.NullInt64
	AssetID             sql.NullInt64
}

func (q *Queries) UpsertAddrEvent(ctx context.Context, arg UpsertAddrEventParams) (int64, error) {
	row := q.db.QueryRowContext(ctx, upsertAddrEvent,
		arg.TaprootOutputKey,
		arg.Txid,
		arg.CreationTime,
		arg.Status,
		arg.ChainTxnOutputIndex,
		arg.ManagedUtxoID,
		arg.AssetProofID,
		arg.AssetID,
	)
	var id int64
	err := row.Scan(&id)
	return id, err
}
