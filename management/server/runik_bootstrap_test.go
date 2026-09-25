package server

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"
)

const (
	testRunikInstanceID  = "default"
	testRunikAccountID   = "runik-account"
	testRunikAccountName = "Runik"
)

func TestRunikBootstrapLifecycleSQLite(t *testing.T) {
	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	am := &DefaultAccountManager{Store: testStore}
	req := testRunikBootstrapRequest()

	first, err := am.RunikBootstrap(ctx, req)
	require.NoError(t, err)
	require.Equal(t, types.RunikBootstrapPhaseBootstrapping, first.Phase)
	require.NotEmpty(t, first.PersonalAccessToken)

	account, err := testStore.GetAccount(ctx, testRunikAccountID)
	require.NoError(t, err)
	require.Len(t, account.Users, 1)
	owner := account.Users[first.OwnerUserID]
	require.NotNil(t, owner)
	require.Equal(t, types.UserRoleOwner, owner.Role)
	require.True(t, owner.IsServiceUser)
	require.True(t, owner.NonDeletable)
	require.Equal(t, runikOwnerName, owner.ServiceUserName)
	require.Equal(t, types.UserIssuedAPI, owner.Issued)

	retry, err := am.RunikBootstrap(ctx, req)
	require.NoError(t, err)
	require.NotEqual(t, first.PersonalAccessToken, retry.PersonalAccessToken)
	pats, err := testStore.GetUserPATs(ctx, store.LockingStrengthNone, retry.OwnerUserID)
	require.NoError(t, err)
	require.Len(t, pats, 1)
	require.Nil(t, pats[0].ExpirationDate)

	_, err = am.SealRunikBootstrap(ctx, testRunikInstanceID, testRunikAccountID, retry.OwnerUserID, "wrong-token")
	require.Error(t, err)
	_, err = am.SealRunikBootstrap(ctx, testRunikInstanceID, "wrong-account", retry.OwnerUserID, retry.PersonalAccessToken)
	require.Error(t, err)
	sealed, err := am.SealRunikBootstrap(ctx, testRunikInstanceID, testRunikAccountID, retry.OwnerUserID, retry.PersonalAccessToken)
	require.NoError(t, err)
	require.Equal(t, types.RunikBootstrapPhaseSealed, sealed.Phase)

	statusResult, err := am.GetRunikBootstrapStatus(ctx, testRunikInstanceID)
	require.NoError(t, err)
	require.Equal(t, types.RunikBootstrapPhaseSealed, statusResult.Phase)
	require.Empty(t, statusResult.PersonalAccessToken)

	_, err = am.RunikBootstrap(ctx, req)
	require.ErrorContains(t, err, "sealed")
	_, err = am.SealRunikBootstrap(ctx, testRunikInstanceID, testRunikAccountID, retry.OwnerUserID, retry.PersonalAccessToken)
	require.ErrorContains(t, err, "sealed")

	credential := RunikOwnerCredentialRequest{
		InstanceID: testRunikInstanceID, Revision: "2026-09-17",
		AccountID: testRunikAccountID, InitiatorUserID: retry.OwnerUserID,
		PlainPAT: retry.PersonalAccessToken,
	}
	_, err = am.VerifyRunikOwnerCredential(ctx, credential)
	require.NoError(t, err)
	prepared, err := am.PrepareRunikOwnerCredentialRotation(ctx, credential)
	require.NoError(t, err)
	require.NotEmpty(t, prepared.PersonalAccessToken)
	pats, err = testStore.GetUserPATs(ctx, store.LockingStrengthNone, retry.OwnerUserID)
	require.NoError(t, err)
	require.Len(t, pats, 2)

	reprepared, err := am.PrepareRunikOwnerCredentialRotation(ctx, credential)
	require.NoError(t, err)
	require.NotEqual(t, prepared.PersonalAccessToken, reprepared.PersonalAccessToken)
	pats, err = testStore.GetUserPATs(ctx, store.LockingStrengthNone, retry.OwnerUserID)
	require.NoError(t, err)
	require.Len(t, pats, 2)

	credential.PlainPAT = reprepared.PersonalAccessToken
	_, err = am.CompleteRunikOwnerCredentialRotation(ctx, credential)
	require.NoError(t, err)
	pats, err = testStore.GetUserPATs(ctx, store.LockingStrengthNone, retry.OwnerUserID)
	require.NoError(t, err)
	require.Len(t, pats, 1)
	require.Equal(t, runikRotationPATName(credential.Revision), pats[0].Name)
	_, err = am.CompleteRunikOwnerCredentialRotation(ctx, credential)
	require.NoError(t, err)
	_, err = am.VerifyRunikOwnerCredential(ctx, credential)
	require.NoError(t, err)
	credential.PlainPAT = retry.PersonalAccessToken
	_, err = am.VerifyRunikOwnerCredential(ctx, credential)
	require.Error(t, err)
}

func TestRunikBootstrapRejectsExistingOrConflictingIdentity(t *testing.T) {
	ctx := context.Background()

	t.Run("existing account without bootstrap state", func(t *testing.T) {
		testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
		require.NoError(t, err)
		t.Cleanup(cleanup)
		require.NoError(t, testStore.SaveAccount(ctx, newAccountWithId(ctx, "existing", "owner", "", "", "", false)))
		am := &DefaultAccountManager{Store: testStore}
		_, err = am.RunikBootstrap(ctx, testRunikBootstrapRequest())
		require.ErrorContains(t, err, "already exists")
	})

	t.Run("changed account identity", func(t *testing.T) {
		testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
		require.NoError(t, err)
		t.Cleanup(cleanup)
		am := &DefaultAccountManager{Store: testStore}
		_, err = am.RunikBootstrap(ctx, testRunikBootstrapRequest())
		require.NoError(t, err)
		changed := testRunikBootstrapRequest()
		changed.AccountID = "another-account"
		_, err = am.RunikBootstrap(ctx, changed)
		require.ErrorContains(t, err, "conflicts")
	})
}

func TestRunikBootstrapAdoptsExistingAccount(t *testing.T) {
	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	account := newAccountWithId(ctx, "existing", "human-owner", "owner@example.com", "", "Owner", false)
	account.Users["member"] = types.NewRegularUser("member", "member@example.com", "Member")
	require.NoError(t, testStore.SaveAccount(ctx, account))
	am := &DefaultAccountManager{Store: testStore}
	req := RunikBootstrapAdoptionRequest{
		InstanceID: testRunikInstanceID, AccountID: "existing", AccountName: testRunikAccountName,
		InitiatorUserID: "human-owner",
	}

	first, err := am.AdoptRunikBootstrap(ctx, req)
	require.NoError(t, err)
	require.NotEmpty(t, first.PersonalAccessToken)
	require.Equal(t, "existing", first.AccountID)

	adopted, err := testStore.GetAccount(ctx, "existing")
	require.NoError(t, err)
	require.Len(t, adopted.Users, 3)
	require.Equal(t, types.UserRoleAdmin, adopted.Users["human-owner"].Role)
	require.Equal(t, types.UserRoleUser, adopted.Users["member"].Role)
	operatorOwner := adopted.Users[first.OwnerUserID]
	require.Equal(t, types.UserRoleOwner, operatorOwner.Role)
	require.True(t, operatorOwner.IsServiceUser)
	require.True(t, operatorOwner.NonDeletable)

	retry, err := am.AdoptRunikBootstrap(ctx, req)
	require.NoError(t, err)
	require.NotEqual(t, first.PersonalAccessToken, retry.PersonalAccessToken)
	pats, err := testStore.GetUserPATs(ctx, store.LockingStrengthNone, retry.OwnerUserID)
	require.NoError(t, err)
	require.Len(t, pats, 1)
}

func TestRunikBootstrapConcurrentRetriesKeepSingleIdentityAndPAT(t *testing.T) {
	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	am := &DefaultAccountManager{Store: testStore}

	const callers = 6
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := am.RunikBootstrap(ctx, testRunikBootstrapRequest())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	require.EqualValues(t, 1, mustAccountCount(t, ctx, testStore))
	account, err := testStore.GetAccount(ctx, testRunikAccountID)
	require.NoError(t, err)
	require.Len(t, account.Users, 1)
	ownerID := runikOwnerID(testRunikInstanceID)
	pats, err := testStore.GetUserPATs(ctx, store.LockingStrengthNone, ownerID)
	require.NoError(t, err)
	require.Len(t, pats, 1)
}

func TestRunikBootstrapLifecyclePostgres(t *testing.T) {
	ctx := context.Background()
	cleanup, dsn, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err)
	t.Cleanup(cleanup)

	testStore, err := store.NewPostgresqlStoreForTests(ctx, dsn, nil, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testStore.Close(context.Background())) })
	am := &DefaultAccountManager{Store: testStore}

	first, err := am.RunikBootstrap(ctx, testRunikBootstrapRequest())
	require.NoError(t, err)
	require.NotEmpty(t, first.PersonalAccessToken)
	retry, err := am.RunikBootstrap(ctx, testRunikBootstrapRequest())
	require.NoError(t, err)
	require.NotEqual(t, first.PersonalAccessToken, retry.PersonalAccessToken)
	_, err = am.SealRunikBootstrap(ctx, testRunikInstanceID, testRunikAccountID, retry.OwnerUserID, retry.PersonalAccessToken)
	require.NoError(t, err)

	account, err := testStore.GetAccount(ctx, testRunikAccountID)
	require.NoError(t, err)
	require.Len(t, account.Users, 1)
	pats, err := testStore.GetUserPATs(ctx, store.LockingStrengthNone, retry.OwnerUserID)
	require.NoError(t, err)
	require.Len(t, pats, 1)
}

func testRunikBootstrapRequest() RunikBootstrapRequest {
	return RunikBootstrapRequest{
		InstanceID: testRunikInstanceID, AccountID: testRunikAccountID, AccountName: testRunikAccountName,
	}
}

func mustAccountCount(t *testing.T, ctx context.Context, testStore store.Store) int64 {
	t.Helper()
	count, err := testStore.GetAccountsCounter(ctx)
	require.NoError(t, err)
	return count
}
