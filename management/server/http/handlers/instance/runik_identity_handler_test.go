package instance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	nbserver "github.com/netbirdio/netbird/management/server"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
)

type runikIdentityManagerStub struct {
	called bool
}

func (s *runikIdentityManagerStub) ReconcileRunikIdentities(_ context.Context, accountID, _ string, req nbserver.RunikIdentitySyncRequest) (*nbserver.RunikIdentitySyncResult, error) {
	s.called = true
	return &nbserver.RunikIdentitySyncResult{AccountID: accountID, Source: req.Source, Revision: req.Revision}, nil
}

func TestRunikIdentityHTTPRequiresPAT(t *testing.T) {
	stub := &runikIdentityManagerStub{}
	h := &runikIdentityHandler{manager: stub}
	router := mux.NewRouter()
	router.HandleFunc("/runik/identity/sync", h.sync).Methods(http.MethodPost)
	body := `{"instance_id":"default","source":"keycloak","revision":"1","complete":true}`

	nonPAT := httptest.NewRequest(http.MethodPost, "/runik/identity/sync", strings.NewReader(body))
	nonPAT = nonPAT.WithContext(nbcontext.SetUserAuthInContext(nonPAT.Context(), auth.UserAuth{AccountId: "account", UserId: "owner"}))
	nonPATRecorder := httptest.NewRecorder()
	router.ServeHTTP(nonPATRecorder, nonPAT)
	require.Equal(t, http.StatusUnauthorized, nonPATRecorder.Code)
	require.False(t, stub.called)

	pat := httptest.NewRequest(http.MethodPost, "/runik/identity/sync", strings.NewReader(body))
	pat = pat.WithContext(nbcontext.SetUserAuthInContext(pat.Context(), auth.UserAuth{AccountId: "account", UserId: "operator-owner", IsPAT: true}))
	patRecorder := httptest.NewRecorder()
	router.ServeHTTP(patRecorder, pat)
	require.Equal(t, http.StatusOK, patRecorder.Code)
	require.True(t, stub.called)
	require.Contains(t, patRecorder.Body.String(), `"account_id":"account"`)
}
