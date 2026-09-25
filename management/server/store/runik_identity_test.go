package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

func TestRunikIdentityMappingsSQLite(t *testing.T) {
	ctx := context.Background()
	testStore, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	sqlStore, ok := testStore.(*SqlStore)
	require.True(t, ok)

	source := &types.RunikIdentitySource{ID: "source-hash", AccountID: "account", Source: "keycloak", InstanceID: "default", Revision: "1", SnapshotHash: "snapshot-hash"}
	user := &types.RunikIdentityUser{ID: "user-hash", AccountID: "account", Source: "keycloak", Issuer: "issuer", Subject: "subject", UserID: "subject"}
	group := &types.RunikIdentityGroup{ID: "group-hash", AccountID: "account", Source: "keycloak", ExternalID: "external-group", GroupID: "internal-group"}
	require.NoError(t, sqlStore.SaveRunikIdentitySource(ctx, source))
	require.NoError(t, sqlStore.SaveRunikIdentityUser(ctx, user))
	require.NoError(t, sqlStore.SaveRunikIdentityGroup(ctx, group))

	storedSource, err := sqlStore.GetRunikIdentitySource(ctx, "account", "keycloak")
	require.NoError(t, err)
	require.Equal(t, "1", storedSource.Revision)
	storedUser, err := sqlStore.GetRunikIdentityUserByUserID(ctx, "subject")
	require.NoError(t, err)
	require.Equal(t, "issuer", storedUser.Issuer)
	storedGroup, err := sqlStore.GetRunikIdentityGroupByGroupID(ctx, "internal-group")
	require.NoError(t, err)
	require.Equal(t, "external-group", storedGroup.ExternalID)
}
