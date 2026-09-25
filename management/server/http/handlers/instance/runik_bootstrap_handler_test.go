package instance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	nbserver "github.com/netbirdio/netbird/management/server"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

type runikBootstrapManagerStub struct {
	phase string
}

func (s *runikBootstrapManagerStub) RunikBootstrap(_ context.Context, req nbserver.RunikBootstrapRequest) (*nbserver.RunikBootstrapResult, error) {
	return &nbserver.RunikBootstrapResult{
		InstanceID: req.InstanceID, AccountID: req.AccountID, AccountName: req.AccountName,
		OwnerUserID: "operator-owner-id", Phase: types.RunikBootstrapPhaseBootstrapping,
		PersonalAccessToken: "nbp_plaintext-once",
	}, nil
}

func (s *runikBootstrapManagerStub) AdoptRunikBootstrap(_ context.Context, req nbserver.RunikBootstrapAdoptionRequest) (*nbserver.RunikBootstrapResult, error) {
	return &nbserver.RunikBootstrapResult{
		InstanceID: req.InstanceID, AccountID: req.AccountID, AccountName: req.AccountName,
		OwnerUserID: "operator-owner-id", Phase: types.RunikBootstrapPhaseBootstrapping,
		PersonalAccessToken: "nbp_adopted-plaintext-once",
	}, nil
}

func (s *runikBootstrapManagerStub) GetRunikBootstrapStatus(_ context.Context, instanceID string) (*nbserver.RunikBootstrapResult, error) {
	return &nbserver.RunikBootstrapResult{InstanceID: instanceID, Phase: s.phase}, nil
}

func (s *runikBootstrapManagerStub) SealRunikBootstrap(_ context.Context, instanceID, _, _, _ string) (*nbserver.RunikBootstrapResult, error) {
	s.phase = types.RunikBootstrapPhaseSealed
	return &nbserver.RunikBootstrapResult{InstanceID: instanceID, Phase: s.phase}, nil
}

func (s *runikBootstrapManagerStub) VerifyRunikOwnerCredential(_ context.Context, req nbserver.RunikOwnerCredentialRequest) (*nbserver.RunikBootstrapResult, error) {
	return &nbserver.RunikBootstrapResult{InstanceID: req.InstanceID, Phase: types.RunikBootstrapPhaseSealed}, nil
}

func (s *runikBootstrapManagerStub) PrepareRunikOwnerCredentialRotation(_ context.Context, req nbserver.RunikOwnerCredentialRequest) (*nbserver.RunikBootstrapResult, error) {
	return &nbserver.RunikBootstrapResult{
		InstanceID: req.InstanceID, Phase: types.RunikBootstrapPhaseSealed,
		PersonalAccessToken: "nbp_rotated-plaintext-once",
	}, nil
}

func (s *runikBootstrapManagerStub) CompleteRunikOwnerCredentialRotation(_ context.Context, req nbserver.RunikOwnerCredentialRequest) (*nbserver.RunikBootstrapResult, error) {
	return &nbserver.RunikBootstrapResult{InstanceID: req.InstanceID, Phase: types.RunikBootstrapPhaseSealed}, nil
}

func TestRunikBootstrapHTTPAuthenticationAndOneTimeResponse(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	secretFile := filepath.Join(t.TempDir(), "bootstrap-secret")
	require.NoError(t, os.WriteFile(secretFile, []byte(secret), 0o600))
	h := &runikBootstrapHandler{manager: &runikBootstrapManagerStub{phase: "pending"}, secretFile: secretFile}
	router := mux.NewRouter()
	router.HandleFunc("/runik/bootstrap", h.bootstrap).Methods(http.MethodPost)
	router.HandleFunc("/runik/bootstrap", h.status).Methods(http.MethodGet)
	router.HandleFunc("/runik/bootstrap/ack", h.ack).Methods(http.MethodPost)
	router.HandleFunc("/runik/bootstrap/adopt", h.adopt).Methods(http.MethodPost)
	router.HandleFunc("/runik/bootstrap/rotate", h.prepareCredentialRotation).Methods(http.MethodPost)
	router.HandleFunc("/runik/bootstrap/rotate/ack", h.completeCredentialRotation).Methods(http.MethodPost)

	body := `{"instance_id":"default","account_id":"account","account_name":"Runik"}`
	unauthorized := httptest.NewRequest(http.MethodPost, "/runik/bootstrap", strings.NewReader(body))
	unauthorizedRecorder := httptest.NewRecorder()
	router.ServeHTTP(unauthorizedRecorder, unauthorized)
	require.Equal(t, http.StatusUnauthorized, unauthorizedRecorder.Code)
	require.NotContains(t, unauthorizedRecorder.Body.String(), "nbp_plaintext-once")

	bootstrap := httptest.NewRequest(http.MethodPost, "/runik/bootstrap", strings.NewReader(body))
	bootstrap.Header.Set("Authorization", "Bearer "+secret)
	bootstrapRecorder := httptest.NewRecorder()
	router.ServeHTTP(bootstrapRecorder, bootstrap)
	require.Equal(t, http.StatusOK, bootstrapRecorder.Code)
	require.Equal(t, "no-store", bootstrapRecorder.Header().Get("Cache-Control"))
	require.Contains(t, bootstrapRecorder.Body.String(), "nbp_plaintext-once")

	statusRequest := httptest.NewRequest(http.MethodGet, "/runik/bootstrap?instance_id=default", nil)
	statusRecorder := httptest.NewRecorder()
	router.ServeHTTP(statusRecorder, statusRequest)
	require.Equal(t, http.StatusOK, statusRecorder.Code)
	require.NotContains(t, statusRecorder.Body.String(), "personal_access_token")

	ackBody := `{"instance_id":"default"}`
	ack := httptest.NewRequest(http.MethodPost, "/runik/bootstrap/ack", strings.NewReader(ackBody))
	ack = ack.WithContext(nbcontext.SetUserAuthInContext(ack.Context(), auth.UserAuth{AccountId: "account", UserId: "operator-owner-id"}))
	ack.Header.Set("Authorization", "Bearer nbp_plaintext-once")
	ackRecorder := httptest.NewRecorder()
	router.ServeHTTP(ackRecorder, ack)
	require.Equal(t, http.StatusOK, ackRecorder.Code)
	require.NotContains(t, ackRecorder.Body.String(), "personal_access_token")

	replay := httptest.NewRequest(http.MethodPost, "/runik/bootstrap", strings.NewReader(body))
	replay.Header.Set("Authorization", "Bearer "+secret)
	replayRecorder := httptest.NewRecorder()
	router.ServeHTTP(replayRecorder, replay)
	require.Equal(t, http.StatusUnauthorized, replayRecorder.Code)

	rotationBody := `{"instance_id":"default","revision":"2026-09-17"}`
	rotate := httptest.NewRequest(http.MethodPost, "/runik/bootstrap/rotate", strings.NewReader(rotationBody))
	rotate = rotate.WithContext(nbcontext.SetUserAuthInContext(rotate.Context(), auth.UserAuth{AccountId: "account", UserId: "operator-owner-id"}))
	rotate.Header.Set("Authorization", "Token nbp_plaintext-once")
	rotateRecorder := httptest.NewRecorder()
	router.ServeHTTP(rotateRecorder, rotate)
	require.Equal(t, http.StatusOK, rotateRecorder.Code)
	require.Equal(t, "no-store", rotateRecorder.Header().Get("Cache-Control"))
	require.Contains(t, rotateRecorder.Body.String(), "nbp_rotated-plaintext-once")

	complete := httptest.NewRequest(http.MethodPost, "/runik/bootstrap/rotate/ack", strings.NewReader(rotationBody))
	complete = complete.WithContext(nbcontext.SetUserAuthInContext(complete.Context(), auth.UserAuth{AccountId: "account", UserId: "operator-owner-id"}))
	complete.Header.Set("Authorization", "Token nbp_rotated-plaintext-once")
	completeRecorder := httptest.NewRecorder()
	router.ServeHTTP(completeRecorder, complete)
	require.Equal(t, http.StatusOK, completeRecorder.Code)
	require.NotContains(t, completeRecorder.Body.String(), "personal_access_token")
}

func TestRunikBootstrapHTTPAdoptionUsesAuthenticatedAccount(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "bootstrap-secret")
	require.NoError(t, os.WriteFile(secretPath, []byte("0123456789abcdef0123456789abcdef"), 0o600))
	h := &runikBootstrapHandler{manager: &runikBootstrapManagerStub{phase: "pending"}, secretFile: secretPath}
	router := mux.NewRouter()
	router.HandleFunc("/runik/bootstrap/adopt", h.adopt).Methods(http.MethodPost)

	body := `{"instance_id":"default","account_name":"Runik"}`
	unauthorized := httptest.NewRequest(http.MethodPost, "/runik/bootstrap/adopt", strings.NewReader(body))
	unauthorizedRecorder := httptest.NewRecorder()
	router.ServeHTTP(unauthorizedRecorder, unauthorized)
	require.Equal(t, http.StatusUnauthorized, unauthorizedRecorder.Code)

	missingOwner := httptest.NewRequest(http.MethodPost, "/runik/bootstrap/adopt", strings.NewReader(body))
	missingOwner.Header.Set("X-Runik-Bootstrap-Secret", "0123456789abcdef0123456789abcdef")
	missingOwnerRecorder := httptest.NewRecorder()
	router.ServeHTTP(missingOwnerRecorder, missingOwner)
	require.Equal(t, http.StatusUnauthorized, missingOwnerRecorder.Code)

	adopt := httptest.NewRequest(http.MethodPost, "/runik/bootstrap/adopt", strings.NewReader(body))
	adopt = adopt.WithContext(nbcontext.SetUserAuthInContext(adopt.Context(), auth.UserAuth{AccountId: "existing-account", UserId: "existing-owner"}))
	adopt.Header.Set("X-Runik-Bootstrap-Secret", "0123456789abcdef0123456789abcdef")
	adoptRecorder := httptest.NewRecorder()
	router.ServeHTTP(adoptRecorder, adopt)
	require.Equal(t, http.StatusOK, adoptRecorder.Code)
	require.Equal(t, "no-store", adoptRecorder.Header().Get("Cache-Control"))
	require.Contains(t, adoptRecorder.Body.String(), "nbp_adopted-plaintext-once")
	require.Contains(t, adoptRecorder.Body.String(), "existing-account")
}
