package server

import (
	"context"
	"sync"
	"testing"

	"github.com/rs/xid"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

const testRunikIdentityIssuer = "https://idp.example.test/realms/runik"

func TestRunikIdentityLifecycleSQLite(t *testing.T) {
	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	testRunikIdentityLifecycle(t, ctx, testStore)
}

func TestRunikIdentityLifecyclePostgres(t *testing.T) {
	ctx := context.Background()
	cleanup, dsn, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err)
	t.Cleanup(cleanup)
	testStore, err := store.NewPostgresqlStoreForTests(ctx, dsn, nil, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testStore.Close(context.Background())) })
	testRunikIdentityLifecycle(t, ctx, testStore)
}

func TestRunikIdentityEmptySnapshotReturnsCompleteDiffs(t *testing.T) {
	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	am, ownerID := sealedRunikIdentityManager(t, ctx, testStore)

	result, err := am.ReconcileRunikIdentities(ctx, testRunikAccountID, ownerID, RunikIdentitySyncRequest{
		InstanceID: testRunikInstanceID,
		Source:     "keycloak",
		Revision:   "empty",
		Complete:   true,
	})
	require.NoError(t, err)
	require.NotNil(t, result.Users)
	require.NotNil(t, result.Groups)
	require.NotNil(t, result.Memberships)
}

func testRunikIdentityLifecycle(t *testing.T, ctx context.Context, testStore store.Store) {
	t.Helper()
	am, ownerID := sealedRunikIdentityManager(t, ctx, testStore)

	unmanaged := &types.Group{ID: "unmanaged", AccountID: testRunikAccountID, PublicID: xid.New().String(), Name: "manual", Issued: types.GroupIssuedAPI}
	jwtGroup := &types.Group{ID: "legacy-jwt", AccountID: testRunikAccountID, PublicID: xid.New().String(), Name: "operators", Issued: types.GroupIssuedJWT}
	duplicateJWTGroup := &types.Group{ID: "legacy-jwt-z", AccountID: testRunikAccountID, PublicID: xid.New().String(), Name: "operators", Issued: types.GroupIssuedJWT}
	require.NoError(t, testStore.CreateGroups(ctx, testRunikAccountID, []*types.Group{unmanaged, jwtGroup, duplicateJWTGroup}))
	alice := types.NewRegularUser("alice-subject", "old@example.test", "Old Alice")
	alice.AccountID = testRunikAccountID
	alice.AutoGroups = []string{unmanaged.ID, duplicateJWTGroup.ID}
	require.NoError(t, testStore.SaveUser(ctx, alice))

	req := RunikIdentitySyncRequest{
		InstanceID: testRunikInstanceID, Source: "keycloak", Revision: "1", Complete: true,
		Users:       []RunikExternalUser{{Issuer: testRunikIdentityIssuer, Subject: alice.Id, Email: "alice@example.test", Name: "Alice", AdoptExisting: true}},
		Groups:      []RunikExternalGroup{{ExternalID: "keycloak-group-1", Name: "operators", AdoptExisting: true}},
		Memberships: []RunikExternalMembership{{Issuer: testRunikIdentityIssuer, Subject: alice.Id, GroupExternalIDs: []string{"keycloak-group-1"}}},
	}
	first, err := am.ReconcileRunikIdentities(ctx, testRunikAccountID, ownerID, req)
	require.NoError(t, err)
	require.True(t, first.Changed)
	require.Equal(t, "adopted", first.Users[0].Action)
	require.Equal(t, "adopted", first.Groups[0].Action)
	require.Equal(t, jwtGroup.ID, first.Groups[0].InternalID)

	storedAlice, err := testStore.GetUserByUserID(ctx, store.LockingStrengthNone, alice.Id)
	require.NoError(t, err)
	require.False(t, storedAlice.Blocked)
	require.ElementsMatch(t, []string{unmanaged.ID, jwtGroup.ID}, storedAlice.AutoGroups)
	require.Equal(t, "Alice", storedAlice.Name)
	accountID, err := am.GetAccountIDByUserID(ctx, auth.UserAuth{UserId: alice.Id})
	require.NoError(t, err)
	require.Equal(t, testRunikAccountID, accountID)

	retry, err := am.ReconcileRunikIdentities(ctx, testRunikAccountID, ownerID, req)
	require.NoError(t, err)
	require.False(t, retry.Changed)
	require.Equal(t, "unchanged", retry.Users[0].Action)

	conflict := req
	conflict.Users = append([]RunikExternalUser(nil), req.Users...)
	conflict.Users[0].Name = "Different content, same revision"
	_, err = am.ReconcileRunikIdentities(ctx, testRunikAccountID, ownerID, conflict)
	require.ErrorContains(t, err, "already used")
	storedAlice, err = testStore.GetUserByUserID(ctx, store.LockingStrengthNone, alice.Id)
	require.NoError(t, err)
	require.Equal(t, "Alice", storedAlice.Name)

	postAdoption := req
	postAdoption.Revision = "2"
	postAdoption.Groups = append([]RunikExternalGroup(nil), req.Groups...)
	postAdoption.Groups[0].AdoptExisting = false
	postAdoptionResult, err := am.ReconcileRunikIdentities(ctx, testRunikAccountID, ownerID, postAdoption)
	require.NoError(t, err)
	require.False(t, postAdoptionResult.Changed)

	renamed := req
	renamed.Revision = "3"
	renamed.Groups = append([]RunikExternalGroup(nil), req.Groups...)
	renamed.Groups[0].Name = "operations"
	renameResult, err := am.ReconcileRunikIdentities(ctx, testRunikAccountID, ownerID, renamed)
	require.NoError(t, err)
	require.Equal(t, "renamed", renameResult.Groups[0].Action)
	require.Equal(t, jwtGroup.ID, renameResult.Groups[0].InternalID)

	empty := RunikIdentitySyncRequest{InstanceID: testRunikInstanceID, Source: "keycloak", Revision: "4", Complete: true}
	emptyResult, err := am.ReconcileRunikIdentities(ctx, testRunikAccountID, ownerID, empty)
	require.NoError(t, err)
	require.True(t, emptyResult.Changed)
	require.Equal(t, "disabled", emptyResult.Users[0].Action)
	require.Equal(t, "retained", emptyResult.Groups[0].Action)
	storedAlice, err = testStore.GetUserByUserID(ctx, store.LockingStrengthNone, alice.Id)
	require.NoError(t, err)
	require.True(t, storedAlice.Blocked)
	require.Equal(t, []string{unmanaged.ID}, storedAlice.AutoGroups)

	owner, err := testStore.GetUserByUserID(ctx, store.LockingStrengthNone, ownerID)
	require.NoError(t, err)
	require.False(t, owner.Blocked)
}

func TestRunikIdentityFailureIsAtomic(t *testing.T) {
	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	am, ownerID := sealedRunikIdentityManager(t, ctx, testStore)
	colliding := types.NewRegularUser("existing-subject", "existing@example.test", "Existing")
	colliding.AccountID = testRunikAccountID
	require.NoError(t, testStore.SaveUser(ctx, colliding))

	req := RunikIdentitySyncRequest{
		InstanceID: testRunikInstanceID, Source: "keycloak", Revision: "1", Complete: true,
		Users:  []RunikExternalUser{{Issuer: testRunikIdentityIssuer, Subject: colliding.Id}},
		Groups: []RunikExternalGroup{{ExternalID: "must-rollback", Name: "must-rollback"}},
	}
	_, err = am.ReconcileRunikIdentities(ctx, testRunikAccountID, ownerID, req)
	require.ErrorContains(t, err, "not explicitly adopted")
	_, err = testStore.GetGroupByName(ctx, store.LockingStrengthNone, testRunikAccountID, "must-rollback")
	require.Error(t, err)

	unauthorized := req
	unauthorized.Users[0].AdoptExisting = true
	_, err = am.ReconcileRunikIdentities(ctx, testRunikAccountID, colliding.Id, unauthorized)
	require.ErrorContains(t, err, "operator owner")
}

func TestRunikIdentityConcurrentSnapshotsDoNotDuplicateObjects(t *testing.T) {
	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	am, ownerID := sealedRunikIdentityManager(t, ctx, testStore)
	req := RunikIdentitySyncRequest{
		InstanceID: testRunikInstanceID, Source: "keycloak", Revision: "1", Complete: true,
		Users:  []RunikExternalUser{{Issuer: testRunikIdentityIssuer, Subject: "bob", Name: "Bob"}},
		Groups: []RunikExternalGroup{{ExternalID: "developers", Name: "developers"}},
	}

	const callers = 4
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := am.ReconcileRunikIdentities(ctx, testRunikAccountID, ownerID, req)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	users, err := testStore.GetAccountUsers(ctx, store.LockingStrengthNone, testRunikAccountID)
	require.NoError(t, err)
	require.Len(t, users, 2)
	groups, err := testStore.GetAccountGroups(ctx, store.LockingStrengthNone, testRunikAccountID)
	require.NoError(t, err)
	require.Len(t, groups, 2)
}

func sealedRunikIdentityManager(t *testing.T, ctx context.Context, testStore store.Store) (*DefaultAccountManager, string) {
	t.Helper()
	am := &DefaultAccountManager{Store: testStore}
	bootstrap, err := am.RunikBootstrap(ctx, testRunikBootstrapRequest())
	require.NoError(t, err)
	_, err = am.SealRunikBootstrap(ctx, testRunikInstanceID, testRunikAccountID, bootstrap.OwnerUserID, bootstrap.PersonalAccessToken)
	require.NoError(t, err)
	return am, bootstrap.OwnerUserID
}
