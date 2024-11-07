// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: transfers.sql

package sqlc

import (
	"context"
	"database/sql"
	"time"
)

const applyPendingOutput = `-- name: ApplyPendingOutput :one
WITH spent_asset AS (
    SELECT genesis_id, asset_group_witness_id, script_version
    FROM assets
    WHERE assets.asset_id = $10
)
INSERT INTO assets (
    genesis_id, version, asset_group_witness_id, script_version, lock_time,
    relative_lock_time, script_key_id, anchor_utxo_id, amount,
    split_commitment_root_hash, split_commitment_root_value, spent
) VALUES (
    (SELECT genesis_id FROM spent_asset),
    $1,
    (SELECT asset_group_witness_id FROM spent_asset),
    (SELECT script_version FROM spent_asset),
    $2, $3, $4, $5, $6,
    $7, $8, $9
)
ON CONFLICT (genesis_id, script_key_id, anchor_utxo_id)
    -- This is a NOP, anchor_utxo_id is one of the unique fields that caused the
    -- conflict.
    DO UPDATE SET anchor_utxo_id = EXCLUDED.anchor_utxo_id
RETURNING asset_id
`

type ApplyPendingOutputParams struct {
	AssetVersion             int32
	LockTime                 sql.NullInt32
	RelativeLockTime         sql.NullInt32
	ScriptKeyID              int64
	AnchorUtxoID             sql.NullInt64
	Amount                   int64
	SplitCommitmentRootHash  []byte
	SplitCommitmentRootValue sql.NullInt64
	Spent                    bool
	SpentAssetID             int64
}

func (q *Queries) ApplyPendingOutput(ctx context.Context, arg ApplyPendingOutputParams) (int64, error) {
	row := q.db.QueryRowContext(ctx, applyPendingOutput,
		arg.AssetVersion,
		arg.LockTime,
		arg.RelativeLockTime,
		arg.ScriptKeyID,
		arg.AnchorUtxoID,
		arg.Amount,
		arg.SplitCommitmentRootHash,
		arg.SplitCommitmentRootValue,
		arg.Spent,
		arg.SpentAssetID,
	)
	var asset_id int64
	err := row.Scan(&asset_id)
	return asset_id, err
}

const deleteAssetWitnesses = `-- name: DeleteAssetWitnesses :exec
DELETE FROM asset_witnesses
WHERE asset_id = $1
`

func (q *Queries) DeleteAssetWitnesses(ctx context.Context, assetID int64) error {
	_, err := q.db.ExecContext(ctx, deleteAssetWitnesses, assetID)
	return err
}

const fetchTransferInputs = `-- name: FetchTransferInputs :many
SELECT input_id, anchor_point, asset_id, script_key, amount
FROM asset_transfer_inputs inputs
WHERE transfer_id = $1
ORDER BY input_id
`

type FetchTransferInputsRow struct {
	InputID     int64
	AnchorPoint []byte
	AssetID     []byte
	ScriptKey   []byte
	Amount      int64
}

func (q *Queries) FetchTransferInputs(ctx context.Context, transferID int64) ([]FetchTransferInputsRow, error) {
	rows, err := q.db.QueryContext(ctx, fetchTransferInputs, transferID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FetchTransferInputsRow
	for rows.Next() {
		var i FetchTransferInputsRow
		if err := rows.Scan(
			&i.InputID,
			&i.AnchorPoint,
			&i.AssetID,
			&i.ScriptKey,
			&i.Amount,
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

const fetchTransferOutputs = `-- name: FetchTransferOutputs :many
SELECT
    output_id, proof_suffix, amount, serialized_witnesses, script_key_local,
    split_commitment_root_hash, split_commitment_root_value, num_passive_assets,
    output_type, proof_courier_addr, proof_delivery_complete, position,
    asset_version, lock_time, relative_lock_time,
    utxos.utxo_id AS anchor_utxo_id,
    utxos.outpoint AS anchor_outpoint,
    utxos.amt_sats AS anchor_value,
    utxos.merkle_root AS anchor_merkle_root,
    utxos.taproot_asset_root AS anchor_taproot_asset_root,
    utxos.tapscript_sibling AS anchor_tapscript_sibling,
    utxos.root_version AS anchor_commitment_version,
    utxo_internal_keys.raw_key AS internal_key_raw_key_bytes,
    utxo_internal_keys.key_family AS internal_key_family,
    utxo_internal_keys.key_index AS internal_key_index,
    script_keys.tweaked_script_key AS script_key_bytes,
    script_keys.tweak AS script_key_tweak,
    script_keys.declared_known AS script_key_declared_known,
    script_key AS script_key_id,
    script_internal_keys.raw_key AS script_key_raw_key_bytes,
    script_internal_keys.key_family AS script_key_family,
    script_internal_keys.key_index AS script_key_index
FROM asset_transfer_outputs outputs
JOIN managed_utxos utxos
  ON outputs.anchor_utxo = utxos.utxo_id
JOIN script_keys
  ON outputs.script_key = script_keys.script_key_id
JOIN internal_keys script_internal_keys
  ON script_keys.internal_key_id = script_internal_keys.key_id
JOIN internal_keys utxo_internal_keys
  ON utxos.internal_key_id = utxo_internal_keys.key_id
WHERE transfer_id = $1
ORDER BY output_id
`

type FetchTransferOutputsRow struct {
	OutputID                 int64
	ProofSuffix              []byte
	Amount                   int64
	SerializedWitnesses      []byte
	ScriptKeyLocal           bool
	SplitCommitmentRootHash  []byte
	SplitCommitmentRootValue sql.NullInt64
	NumPassiveAssets         int32
	OutputType               int16
	ProofCourierAddr         []byte
	ProofDeliveryComplete    sql.NullBool
	Position                 int32
	AssetVersion             int32
	LockTime                 sql.NullInt32
	RelativeLockTime         sql.NullInt32
	AnchorUtxoID             int64
	AnchorOutpoint           []byte
	AnchorValue              int64
	AnchorMerkleRoot         []byte
	AnchorTaprootAssetRoot   []byte
	AnchorTapscriptSibling   []byte
	AnchorCommitmentVersion  sql.NullInt16
	InternalKeyRawKeyBytes   []byte
	InternalKeyFamily        int32
	InternalKeyIndex         int32
	ScriptKeyBytes           []byte
	ScriptKeyTweak           []byte
	ScriptKeyDeclaredKnown   sql.NullBool
	ScriptKeyID              int64
	ScriptKeyRawKeyBytes     []byte
	ScriptKeyFamily          int32
	ScriptKeyIndex           int32
}

func (q *Queries) FetchTransferOutputs(ctx context.Context, transferID int64) ([]FetchTransferOutputsRow, error) {
	rows, err := q.db.QueryContext(ctx, fetchTransferOutputs, transferID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FetchTransferOutputsRow
	for rows.Next() {
		var i FetchTransferOutputsRow
		if err := rows.Scan(
			&i.OutputID,
			&i.ProofSuffix,
			&i.Amount,
			&i.SerializedWitnesses,
			&i.ScriptKeyLocal,
			&i.SplitCommitmentRootHash,
			&i.SplitCommitmentRootValue,
			&i.NumPassiveAssets,
			&i.OutputType,
			&i.ProofCourierAddr,
			&i.ProofDeliveryComplete,
			&i.Position,
			&i.AssetVersion,
			&i.LockTime,
			&i.RelativeLockTime,
			&i.AnchorUtxoID,
			&i.AnchorOutpoint,
			&i.AnchorValue,
			&i.AnchorMerkleRoot,
			&i.AnchorTaprootAssetRoot,
			&i.AnchorTapscriptSibling,
			&i.AnchorCommitmentVersion,
			&i.InternalKeyRawKeyBytes,
			&i.InternalKeyFamily,
			&i.InternalKeyIndex,
			&i.ScriptKeyBytes,
			&i.ScriptKeyTweak,
			&i.ScriptKeyDeclaredKnown,
			&i.ScriptKeyID,
			&i.ScriptKeyRawKeyBytes,
			&i.ScriptKeyFamily,
			&i.ScriptKeyIndex,
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

const insertAssetTransfer = `-- name: InsertAssetTransfer :one
WITH target_txn(txn_id) AS (
    SELECT txn_id
    FROM chain_txns
    WHERE txid = $3
)
INSERT INTO asset_transfers (
    height_hint, anchor_txn_id, transfer_time_unix
) VALUES (
    $1, (SELECT txn_id FROM target_txn), $2
) RETURNING id
`

type InsertAssetTransferParams struct {
	HeightHint       int32
	TransferTimeUnix time.Time
	AnchorTxid       []byte
}

func (q *Queries) InsertAssetTransfer(ctx context.Context, arg InsertAssetTransferParams) (int64, error) {
	row := q.db.QueryRowContext(ctx, insertAssetTransfer, arg.HeightHint, arg.TransferTimeUnix, arg.AnchorTxid)
	var id int64
	err := row.Scan(&id)
	return id, err
}

const insertAssetTransferInput = `-- name: InsertAssetTransferInput :exec
INSERT INTO asset_transfer_inputs (
    transfer_id, anchor_point, asset_id, script_key, amount
) VALUES (
    $1, $2, $3, $4, $5
)
`

type InsertAssetTransferInputParams struct {
	TransferID  int64
	AnchorPoint []byte
	AssetID     []byte
	ScriptKey   []byte
	Amount      int64
}

func (q *Queries) InsertAssetTransferInput(ctx context.Context, arg InsertAssetTransferInputParams) error {
	_, err := q.db.ExecContext(ctx, insertAssetTransferInput,
		arg.TransferID,
		arg.AnchorPoint,
		arg.AssetID,
		arg.ScriptKey,
		arg.Amount,
	)
	return err
}

const insertAssetTransferOutput = `-- name: InsertAssetTransferOutput :exec
INSERT INTO asset_transfer_outputs (
    transfer_id, anchor_utxo, script_key, script_key_local,
    amount, serialized_witnesses, split_commitment_root_hash,
    split_commitment_root_value, proof_suffix, num_passive_assets,
    output_type, proof_courier_addr, asset_version, lock_time,
    relative_lock_time, proof_delivery_complete, position
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
)
`

type InsertAssetTransferOutputParams struct {
	TransferID               int64
	AnchorUtxo               int64
	ScriptKey                int64
	ScriptKeyLocal           bool
	Amount                   int64
	SerializedWitnesses      []byte
	SplitCommitmentRootHash  []byte
	SplitCommitmentRootValue sql.NullInt64
	ProofSuffix              []byte
	NumPassiveAssets         int32
	OutputType               int16
	ProofCourierAddr         []byte
	AssetVersion             int32
	LockTime                 sql.NullInt32
	RelativeLockTime         sql.NullInt32
	ProofDeliveryComplete    sql.NullBool
	Position                 int32
}

func (q *Queries) InsertAssetTransferOutput(ctx context.Context, arg InsertAssetTransferOutputParams) error {
	_, err := q.db.ExecContext(ctx, insertAssetTransferOutput,
		arg.TransferID,
		arg.AnchorUtxo,
		arg.ScriptKey,
		arg.ScriptKeyLocal,
		arg.Amount,
		arg.SerializedWitnesses,
		arg.SplitCommitmentRootHash,
		arg.SplitCommitmentRootValue,
		arg.ProofSuffix,
		arg.NumPassiveAssets,
		arg.OutputType,
		arg.ProofCourierAddr,
		arg.AssetVersion,
		arg.LockTime,
		arg.RelativeLockTime,
		arg.ProofDeliveryComplete,
		arg.Position,
	)
	return err
}

const insertBurn = `-- name: InsertBurn :one
INSERT INTO asset_burn_transfers (
    transfer_id, note, asset_id, group_key, amount
)
VALUES (
    $1, $2, $3, $4, $5
)
RETURNING burn_id
`

type InsertBurnParams struct {
	TransferID int32
	Note       sql.NullString
	AssetID    []byte
	GroupKey   []byte
	Amount     int64
}

func (q *Queries) InsertBurn(ctx context.Context, arg InsertBurnParams) (int64, error) {
	row := q.db.QueryRowContext(ctx, insertBurn,
		arg.TransferID,
		arg.Note,
		arg.AssetID,
		arg.GroupKey,
		arg.Amount,
	)
	var burn_id int64
	err := row.Scan(&burn_id)
	return burn_id, err
}

const insertPassiveAsset = `-- name: InsertPassiveAsset :exec
WITH target_asset(asset_id) AS (
    SELECT assets.asset_id
    FROM assets
        JOIN genesis_assets
            ON assets.genesis_id = genesis_assets.gen_asset_id
        JOIN managed_utxos utxos
            ON assets.anchor_utxo_id = utxos.utxo_id
        JOIN script_keys
            ON assets.script_key_id = script_keys.script_key_id
    WHERE genesis_assets.asset_id = $7
        AND utxos.outpoint = $8
        AND script_keys.tweaked_script_key = $3
)
INSERT INTO passive_assets (
    asset_id, transfer_id, new_anchor_utxo, script_key, new_witness_stack,
    new_proof, asset_version
) VALUES (
    (SELECT asset_id FROM target_asset), $1, $2,
    $3, $4, $5, $6
)
`

type InsertPassiveAssetParams struct {
	TransferID      int64
	NewAnchorUtxo   int64
	ScriptKey       []byte
	NewWitnessStack []byte
	NewProof        []byte
	AssetVersion    int32
	AssetGenesisID  []byte
	PrevOutpoint    []byte
}

func (q *Queries) InsertPassiveAsset(ctx context.Context, arg InsertPassiveAssetParams) error {
	_, err := q.db.ExecContext(ctx, insertPassiveAsset,
		arg.TransferID,
		arg.NewAnchorUtxo,
		arg.ScriptKey,
		arg.NewWitnessStack,
		arg.NewProof,
		arg.AssetVersion,
		arg.AssetGenesisID,
		arg.PrevOutpoint,
	)
	return err
}

const logProofTransferAttempt = `-- name: LogProofTransferAttempt :exec
INSERT INTO proof_transfer_log (
    transfer_type, proof_locator_hash, time_unix
) VALUES (
    $1, $2, $3
)
`

type LogProofTransferAttemptParams struct {
	TransferType     string
	ProofLocatorHash []byte
	TimeUnix         time.Time
}

func (q *Queries) LogProofTransferAttempt(ctx context.Context, arg LogProofTransferAttemptParams) error {
	_, err := q.db.ExecContext(ctx, logProofTransferAttempt, arg.TransferType, arg.ProofLocatorHash, arg.TimeUnix)
	return err
}

const queryAssetTransfers = `-- name: QueryAssetTransfers :many
SELECT
    id, height_hint, txns.txid, txns.block_hash AS anchor_tx_block_hash,
    transfer_time_unix
FROM asset_transfers transfers
JOIN chain_txns txns
    ON txns.txn_id = transfers.anchor_txn_id
WHERE
    -- Optionally filter on a given anchor_tx_hash.
    (txns.txid = $1
        OR $1 IS NULL)

    -- Filter for pending transfers only if requested.
    AND (
        $2 = true AND
        (
            txns.block_hash IS NULL
                OR EXISTS (
                    SELECT 1
                    FROM asset_transfer_outputs outputs
                    WHERE outputs.transfer_id = transfers.id
                      AND outputs.proof_delivery_complete = false
                )
        )
        OR $2 = false OR $2 IS NULL
    )
ORDER BY transfer_time_unix
`

type QueryAssetTransfersParams struct {
	AnchorTxHash         []byte
	PendingTransfersOnly interface{}
}

type QueryAssetTransfersRow struct {
	ID                int64
	HeightHint        int32
	Txid              []byte
	AnchorTxBlockHash []byte
	TransferTimeUnix  time.Time
}

func (q *Queries) QueryAssetTransfers(ctx context.Context, arg QueryAssetTransfersParams) ([]QueryAssetTransfersRow, error) {
	rows, err := q.db.QueryContext(ctx, queryAssetTransfers, arg.AnchorTxHash, arg.PendingTransfersOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []QueryAssetTransfersRow
	for rows.Next() {
		var i QueryAssetTransfersRow
		if err := rows.Scan(
			&i.ID,
			&i.HeightHint,
			&i.Txid,
			&i.AnchorTxBlockHash,
			&i.TransferTimeUnix,
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

const queryBurns = `-- name: QueryBurns :many
SELECT
    abt.note,
    abt.asset_id,
    abt.group_key,
    abt.amount,
    ct.txid AS anchor_txid -- Retrieving the txid from chain_txns.
FROM asset_burn_transfers abt
JOIN asset_transfers at ON abt.transfer_id = at.id
JOIN chain_txns ct ON at.anchor_txn_id = ct.txn_id
WHERE
    -- Optionally filter by asset_id.
    (abt.asset_id = $1 OR $1 IS NULL)

    -- Optionally filter by group_key.
    AND (abt.group_key = $2 OR $2 IS NULL)

    -- Optionally filter by anchor_txid in chain_txns.txid.
    AND (ct.txid = $3 OR $3 IS NULL)
ORDER BY abt.burn_id
`

type QueryBurnsParams struct {
	AssetID    []byte
	GroupKey   []byte
	AnchorTxid []byte
}

type QueryBurnsRow struct {
	Note       sql.NullString
	AssetID    []byte
	GroupKey   []byte
	Amount     int64
	AnchorTxid []byte
}

func (q *Queries) QueryBurns(ctx context.Context, arg QueryBurnsParams) ([]QueryBurnsRow, error) {
	rows, err := q.db.QueryContext(ctx, queryBurns, arg.AssetID, arg.GroupKey, arg.AnchorTxid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []QueryBurnsRow
	for rows.Next() {
		var i QueryBurnsRow
		if err := rows.Scan(
			&i.Note,
			&i.AssetID,
			&i.GroupKey,
			&i.Amount,
			&i.AnchorTxid,
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

const queryPassiveAssets = `-- name: QueryPassiveAssets :many
SELECT passive.asset_id, passive.new_anchor_utxo, passive.script_key,
       passive.new_witness_stack, passive.new_proof,
       genesis_assets.asset_id AS genesis_id, passive.asset_version,
       utxos.outpoint
FROM passive_assets as passive
    JOIN assets
        ON passive.asset_id = assets.asset_id
    JOIN genesis_assets
        ON assets.genesis_id = genesis_assets.gen_asset_id
    JOIN managed_utxos utxos
        ON passive.new_anchor_utxo = utxos.utxo_id
WHERE passive.transfer_id = $1
`

type QueryPassiveAssetsRow struct {
	AssetID         int64
	NewAnchorUtxo   int64
	ScriptKey       []byte
	NewWitnessStack []byte
	NewProof        []byte
	GenesisID       []byte
	AssetVersion    int32
	Outpoint        []byte
}

func (q *Queries) QueryPassiveAssets(ctx context.Context, transferID int64) ([]QueryPassiveAssetsRow, error) {
	rows, err := q.db.QueryContext(ctx, queryPassiveAssets, transferID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []QueryPassiveAssetsRow
	for rows.Next() {
		var i QueryPassiveAssetsRow
		if err := rows.Scan(
			&i.AssetID,
			&i.NewAnchorUtxo,
			&i.ScriptKey,
			&i.NewWitnessStack,
			&i.NewProof,
			&i.GenesisID,
			&i.AssetVersion,
			&i.Outpoint,
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

const queryProofTransferAttempts = `-- name: QueryProofTransferAttempts :many
SELECT time_unix
FROM proof_transfer_log
WHERE proof_locator_hash = $1
    AND transfer_type = $2
ORDER BY time_unix DESC
`

type QueryProofTransferAttemptsParams struct {
	ProofLocatorHash []byte
	TransferType     string
}

func (q *Queries) QueryProofTransferAttempts(ctx context.Context, arg QueryProofTransferAttemptsParams) ([]time.Time, error) {
	rows, err := q.db.QueryContext(ctx, queryProofTransferAttempts, arg.ProofLocatorHash, arg.TransferType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []time.Time
	for rows.Next() {
		var time_unix time.Time
		if err := rows.Scan(&time_unix); err != nil {
			return nil, err
		}
		items = append(items, time_unix)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const reAnchorPassiveAssets = `-- name: ReAnchorPassiveAssets :exec
UPDATE assets
SET anchor_utxo_id = $1,
    split_commitment_root_hash = NULL,
    split_commitment_root_value = NULL
WHERE asset_id = $2
`

type ReAnchorPassiveAssetsParams struct {
	NewAnchorUtxoID sql.NullInt64
	AssetID         int64
}

func (q *Queries) ReAnchorPassiveAssets(ctx context.Context, arg ReAnchorPassiveAssetsParams) error {
	_, err := q.db.ExecContext(ctx, reAnchorPassiveAssets, arg.NewAnchorUtxoID, arg.AssetID)
	return err
}

const setTransferOutputProofDeliveryStatus = `-- name: SetTransferOutputProofDeliveryStatus :exec
WITH target(output_id) AS (
    SELECT output_id
    FROM asset_transfer_outputs output
    JOIN managed_utxos
      ON output.anchor_utxo = managed_utxos.utxo_id
    WHERE managed_utxos.outpoint = $2
      AND output.position = $3
)
UPDATE asset_transfer_outputs
SET proof_delivery_complete = $1
WHERE output_id = (SELECT output_id FROM target)
`

type SetTransferOutputProofDeliveryStatusParams struct {
	DeliveryComplete         sql.NullBool
	SerializedAnchorOutpoint []byte
	Position                 int32
}

func (q *Queries) SetTransferOutputProofDeliveryStatus(ctx context.Context, arg SetTransferOutputProofDeliveryStatusParams) error {
	_, err := q.db.ExecContext(ctx, setTransferOutputProofDeliveryStatus, arg.DeliveryComplete, arg.SerializedAnchorOutpoint, arg.Position)
	return err
}
