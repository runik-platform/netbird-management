//go:build !ios

package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/testutil"
)

// TestRunikPostgresUpgrade verifies the database contract used by the Runik
// image: a first Management start applies the complete migration chain, and a
// second start over the same disposable database is idempotent and preserves
// user data.
func TestRunikPostgresUpgrade(t *testing.T) {
	ctx := context.Background()
	cleanup, dsn, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err)
	t.Cleanup(cleanup)

	first, err := NewPostgresqlStoreForTests(ctx, dsn, nil, false)
	require.NoError(t, err)

	const (
		accountID = "runik-upgrade-account"
		ownerID   = "runik-upgrade-owner"
	)
	require.NoError(t, first.SaveAccount(ctx, newAccountWithId(ctx, accountID, ownerID, "runik.invalid")))
	closeRunikPostgresStore(t, first)

	second, err := NewPostgresqlStoreForTests(ctx, dsn, nil, false)
	require.NoError(t, err)
	t.Cleanup(func() { closeRunikPostgresStore(t, second) })

	account, err := second.GetAccount(ctx, accountID)
	require.NoError(t, err)
	require.Equal(t, accountID, account.Id)
	require.Contains(t, account.Users, ownerID)
	require.NoError(t, second.LockRunikIdentitySource(ctx, accountID, "keycloak-example"))
}

func closeRunikPostgresStore(t *testing.T, store *SqlStore) {
	t.Helper()
	if store.pool != nil {
		store.pool.Close()
	}
	require.NoError(t, store.Close(context.Background()))
}
