package instance

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/mux"

	nbserver "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type runikIdentityManager interface {
	ReconcileRunikIdentities(ctx context.Context, accountID, initiatorUserID string, req nbserver.RunikIdentitySyncRequest) (*nbserver.RunikIdentitySyncResult, error)
}

type runikIdentityHandler struct {
	manager runikIdentityManager
}

// AddRunikIdentityEndpoints registers the authenticated operator-only identity
// reconciliation primitive. Unlike bootstrap, this route is never bypassed by
// the regular JWT/PAT authentication middleware.
func AddRunikIdentityEndpoints(accountManager account.Manager, router *mux.Router) {
	manager, ok := accountManager.(runikIdentityManager)
	if !ok {
		return
	}
	h := &runikIdentityHandler{manager: manager}
	router.HandleFunc("/runik/identity/sync", h.sync).Methods(http.MethodPost, http.MethodOptions)
}

func (h *runikIdentityHandler) sync(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil || !userAuth.IsPAT {
		util.WriteError(r.Context(), status.Errorf(status.Unauthorized, "a personal access token is required"), w)
		return
	}
	var req nbserver.RunikIdentitySyncRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid identity snapshot"), w)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "request body must contain one JSON object"), w)
		return
	}
	result, err := h.manager.ReconcileRunikIdentities(r.Context(), userAuth.AccountId, userAuth.UserId, req)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, result)
}
