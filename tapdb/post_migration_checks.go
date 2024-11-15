package tapdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightningnetwork/lnd/clock"
)

// postMigrationCheck is a function type for a function that performs a
// post-migration check on the database.
type postMigrationCheck func(context.Context, sqlc.Querier) error

var (
	// postMigrationChecks is a list of functions that are run after the
	// database migrations have been applied. These functions are used to
	// perform additional checks on the database state that are not fully
	// expressible in SQL.
	postMigrationChecks = []postMigrationCheck{
		detectScriptKeyType,
	}
)

// runPostMigrationChecks runs a set of post-migration checks on the database
// using the given database backend.
func runPostMigrationChecks(db DatabaseBackend) error {
	var (
		ctx  = context.Background()
		txDb = NewTransactionExecutor(
			db, func(tx *sql.Tx) sqlc.Querier {
				return db.WithTx(tx)
			},
		)
		writeTxOpts AssetStoreTxOptions
	)

	return txDb.ExecTx(ctx, &writeTxOpts, func(q sqlc.Querier) error {
		log.Infof("Running %d post-migration checks",
			len(postMigrationChecks))
		start := time.Now()

		for _, check := range postMigrationChecks {
			err := check(ctx, q)
			if err != nil {
				return err
			}
		}

		log.Infof("Post-migration checks completed in %v",
			time.Since(start))

		return nil
	})
}

// detectScriptKeyType attempts to detect the type of the script keys that don't
// have a type set yet.
func detectScriptKeyType(ctx context.Context, q sqlc.Querier) error {
	defaultClock := clock.NewDefaultClock()

	// We start by fetching all assets, even the spent ones. We then collect
	// a list of the burn keys from the assets (because burn keys can only
	// be calculated from the asset's witness).
	assetFilter := QueryAssetFilters{
		Now: sql.NullTime{
			Time:  defaultClock.Now().UTC(),
			Valid: true,
		},
	}
	dbAssets, assetWitnesses, err := fetchAssetsWithWitness(
		ctx, q, assetFilter,
	)
	if err != nil {
		return fmt.Errorf("error fetching assets: %w", err)
	}

	chainAssets, err := dbAssetsToChainAssets(
		dbAssets, assetWitnesses, defaultClock,
	)
	if err != nil {
		return fmt.Errorf("error converting assets: %w", err)
	}

	burnAssets := fn.Filter(chainAssets, func(a *asset.ChainAsset) bool {
		return a.IsBurn()
	})
	burnKeys := make(map[asset.SerializedKey]struct{})
	for _, a := range burnAssets {
		serializedKey := asset.ToSerialized(a.ScriptKey.PubKey)
		burnKeys[serializedKey] = struct{}{}
	}

	untypedKeys, err := q.FetchUnknownTypeScriptKeys(ctx)
	if err != nil {
		return fmt.Errorf("error fetching script keys: %w", err)
	}

	channelFundingKey := asset.NewScriptKey(
		tapscript.NewChannelFundingScriptTree().TaprootKey,
	).PubKey

	for _, k := range untypedKeys {
		scriptKey, err := parseScriptKey(k.InternalKey, k.ScriptKey)
		if err != nil {
			return fmt.Errorf("error parsing script key: %w", err)
		}

		serializedKey := asset.ToSerialized(scriptKey.PubKey)
		newType := asset.ScriptKeyUnknown

		if _, ok := burnKeys[serializedKey]; ok {
			newType = asset.ScriptKeyBurn
		} else {
			guessedType := scriptKey.GuessType()
			if guessedType == asset.ScriptKeyBip86 {
				newType = asset.ScriptKeyBip86
			}

			if guessedType == asset.ScriptKeyScriptPathExternal &&
				scriptKey.PubKey.IsEqual(channelFundingKey) {

				newType = asset.ScriptKeyScriptPathChannel
			}
		}

		// If we were able to identify the key type, we update the key
		// in the database.
		if newType != asset.ScriptKeyUnknown {
			_, err := q.UpsertScriptKey(ctx, NewScriptKey{
				InternalKeyID:    k.InternalKey.KeyID,
				TweakedScriptKey: k.ScriptKey.TweakedScriptKey,
				Tweak:            k.ScriptKey.Tweak,
				DeclaredKnown:    k.ScriptKey.DeclaredKnown,
				KeyType:          sqlInt16(newType),
			})
			if err != nil {
				return fmt.Errorf("error updating script key "+
					"type: %w", err)
			}
		}
	}

	return nil
}
