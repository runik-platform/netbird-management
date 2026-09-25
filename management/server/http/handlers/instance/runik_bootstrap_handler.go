package instance

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"

	nbserver "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

const RunikBootstrapSecretFileEnvKey = "NB_RUNIK_BOOTSTRAP_SECRET_FILE"

type runikBootstrapManager interface {
	RunikBootstrap(rctx context.Context, req nbserver.RunikBootstrapRequest) (*nbserver.RunikBootstrapResult, error)
	AdoptRunikBootstrap(rctx context.Context, req nbserver.RunikBootstrapAdoptionRequest) (*nbserver.RunikBootstrapResult, error)
	GetRunikBootstrapStatus(rctx context.Context, instanceID string) (*nbserver.RunikBootstrapResult, error)
	SealRunikBootstrap(rctx context.Context, instanceID, accountID, userID, plainPAT string) (*nbserver.RunikBootstrapResult, error)
	VerifyRunikOwnerCredential(rctx context.Context, req nbserver.RunikOwnerCredentialRequest) (*nbserver.RunikBootstrapResult, error)
	PrepareRunikOwnerCredentialRotation(rctx context.Context, req nbserver.RunikOwnerCredentialRequest) (*nbserver.RunikBootstrapResult, error)
	CompleteRunikOwnerCredentialRotation(rctx context.Context, req nbserver.RunikOwnerCredentialRequest) (*nbserver.RunikBootstrapResult, error)
}

type runikBootstrapHandler struct {
	manager    runikBootstrapManager
	secretFile string
}

type runikBootstrapRequest struct {
	InstanceID  string `json:"instance_id"`
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name"`
}

type runikBootstrapAckRequest struct {
	InstanceID string `json:"instance_id"`
}

type runikBootstrapAdoptionRequest struct {
	InstanceID  string `json:"instance_id"`
	AccountName string `json:"account_name"`
}

type runikOwnerCredentialRequest struct {
	InstanceID string `json:"instance_id"`
	Revision   string `json:"revision,omitempty"`
}

type runikBootstrapResponse struct {
	InstanceID          string  `json:"instance_id"`
	AccountID           string  `json:"account_id,omitempty"`
	AccountName         string  `json:"account_name,omitempty"`
	OwnerUserID         string  `json:"owner_user_id,omitempty"`
	Phase               string  `json:"phase"`
	PersonalAccessToken *string `json:"personal_access_token,omitempty"`
}

// AddRunikBootstrapEndpoints registers the Runik bootstrap status query. The
// mutation routes are present only when an out-of-database credential file is
// configured; after the mount is removed, only credential-free status remains.
func AddRunikBootstrapEndpoints(accountManager account.Manager, router *mux.Router) error {
	secretFile := strings.TrimSpace(os.Getenv(RunikBootstrapSecretFileEnvKey))
	manager, ok := accountManager.(runikBootstrapManager)
	if !ok {
		return nil
	}
	h := &runikBootstrapHandler{manager: manager, secretFile: secretFile}
	router.HandleFunc("/runik/bootstrap", h.status).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc("/runik/bootstrap/verify", h.verifyCredential).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/runik/bootstrap/rotate", h.prepareCredentialRotation).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/runik/bootstrap/rotate/ack", h.completeCredentialRotation).Methods(http.MethodPost, http.MethodOptions)
	if secretFile == "" {
		return nil
	}
	router.HandleFunc("/runik/bootstrap", h.bootstrap).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/runik/bootstrap/adopt", h.adopt).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/runik/bootstrap/ack", h.ack).Methods(http.MethodPost, http.MethodOptions)
	return nil
}

func (h *runikBootstrapHandler) verifyCredential(w http.ResponseWriter, r *http.Request) {
	_, credential, err := authenticatedRunikCredentialRequest(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result, err := h.manager.VerifyRunikOwnerCredential(r.Context(), credential)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, newRunikBootstrapResponse(result, false))
}

func (h *runikBootstrapHandler) prepareCredentialRotation(w http.ResponseWriter, r *http.Request) {
	_, credential, err := authenticatedRunikCredentialRequest(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result, err := h.manager.PrepareRunikOwnerCredentialRotation(r.Context(), credential)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	util.WriteJSONObject(r.Context(), w, newRunikBootstrapResponse(result, true))
}

func (h *runikBootstrapHandler) completeCredentialRotation(w http.ResponseWriter, r *http.Request) {
	_, credential, err := authenticatedRunikCredentialRequest(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result, err := h.manager.CompleteRunikOwnerCredentialRotation(r.Context(), credential)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	util.WriteJSONObject(r.Context(), w, newRunikBootstrapResponse(result, false))
}

func authenticatedRunikCredentialRequest(r *http.Request) (runikOwnerCredentialRequest, nbserver.RunikOwnerCredentialRequest, error) {
	var req runikOwnerCredentialRequest
	if err := decodeRunikRequest(r, &req); err != nil {
		return req, nbserver.RunikOwnerCredentialRequest{}, err
	}
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		return req, nbserver.RunikOwnerCredentialRequest{}, status.Errorf(status.Unauthorized, "authenticated PAT identity is missing")
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !(strings.EqualFold(parts[0], "Bearer") || strings.EqualFold(parts[0], "Token")) {
		return req, nbserver.RunikOwnerCredentialRequest{}, status.Errorf(status.Unauthorized, "personal access token is missing")
	}
	return req, nbserver.RunikOwnerCredentialRequest{
		InstanceID: req.InstanceID, Revision: req.Revision,
		AccountID: userAuth.AccountId, InitiatorUserID: userAuth.UserId, PlainPAT: parts[1],
	}, nil
}

func (h *runikBootstrapHandler) adopt(w http.ResponseWriter, r *http.Request) {
	var req runikBootstrapAdoptionRequest
	if err := decodeRunikRequest(r, &req); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := h.authorizeAdoption(r, req.InstanceID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Unauthorized, "authenticated adoption identity is missing"), w)
		return
	}
	result, err := h.manager.AdoptRunikBootstrap(r.Context(), nbserver.RunikBootstrapAdoptionRequest{
		InstanceID: req.InstanceID, AccountID: userAuth.AccountId,
		AccountName: req.AccountName, InitiatorUserID: userAuth.UserId,
	})
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	util.WriteJSONObject(r.Context(), w, newRunikBootstrapResponse(result, true))
}

func (h *runikBootstrapHandler) authorizeAdoption(r *http.Request, instanceID string) error {
	state, err := h.manager.GetRunikBootstrapStatus(r.Context(), instanceID)
	if err != nil {
		return err
	}
	if state.Phase == types.RunikBootstrapPhaseSealed {
		return status.Errorf(status.Unauthorized, "runik bootstrap is sealed")
	}

	expected, err := os.ReadFile(h.secretFile)
	if err != nil {
		return status.Errorf(status.Unauthorized, "bootstrap credential is unavailable")
	}
	expectedSecret := strings.TrimSpace(string(expected))
	presentedSecret := strings.TrimSpace(r.Header.Get("X-Runik-Bootstrap-Secret"))
	if len(expectedSecret) < 32 || subtle.ConstantTimeCompare([]byte(presentedSecret), []byte(expectedSecret)) != 1 {
		return status.Errorf(status.Unauthorized, "bootstrap credential is invalid")
	}
	return nil
}

func (h *runikBootstrapHandler) status(w http.ResponseWriter, r *http.Request) {
	result, err := h.manager.GetRunikBootstrapStatus(r.Context(), r.URL.Query().Get("instance_id"))
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, newRunikBootstrapResponse(result, false))
}

func (h *runikBootstrapHandler) bootstrap(w http.ResponseWriter, r *http.Request) {
	var req runikBootstrapRequest
	if err := decodeRunikRequest(r, &req); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if err := h.authorize(r, req.InstanceID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result, err := h.manager.RunikBootstrap(r.Context(), nbserver.RunikBootstrapRequest{
		InstanceID: req.InstanceID, AccountID: req.AccountID, AccountName: req.AccountName,
	})
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	util.WriteJSONObject(r.Context(), w, newRunikBootstrapResponse(result, true))
}

func (h *runikBootstrapHandler) ack(w http.ResponseWriter, r *http.Request) {
	var req runikBootstrapAckRequest
	if err := decodeRunikRequest(r, &req); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.Unauthorized, "authenticated PAT identity is missing"), w)
		return
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !(strings.EqualFold(parts[0], "Bearer") || strings.EqualFold(parts[0], "Token")) {
		util.WriteError(r.Context(), status.Errorf(status.Unauthorized, "personal access token is missing"), w)
		return
	}
	result, err := h.manager.SealRunikBootstrap(r.Context(), req.InstanceID, userAuth.AccountId, userAuth.UserId, parts[1])
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	util.WriteJSONObject(r.Context(), w, newRunikBootstrapResponse(result, false))
}

func (h *runikBootstrapHandler) authorize(r *http.Request, instanceID string) error {
	state, err := h.manager.GetRunikBootstrapStatus(r.Context(), instanceID)
	if err != nil {
		return err
	}
	if state.Phase == types.RunikBootstrapPhaseSealed {
		return status.Errorf(status.Unauthorized, "runik bootstrap is sealed")
	}

	expected, err := os.ReadFile(h.secretFile)
	if err != nil {
		return status.Errorf(status.Unauthorized, "bootstrap credential is unavailable")
	}
	expectedSecret := strings.TrimSpace(string(expected))
	if len(expectedSecret) < 32 {
		return status.Errorf(status.Unauthorized, "bootstrap credential is invalid")
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") ||
		subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedSecret)) != 1 {
		return status.Errorf(status.Unauthorized, "bootstrap credential is invalid")
	}
	return nil
}

func decodeRunikRequest(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid request body")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return status.Errorf(status.InvalidArgument, "request body must contain one JSON object")
	}
	return nil
}

func newRunikBootstrapResponse(result *nbserver.RunikBootstrapResult, includePAT bool) runikBootstrapResponse {
	response := runikBootstrapResponse{
		InstanceID: result.InstanceID, AccountID: result.AccountID, AccountName: result.AccountName,
		OwnerUserID: result.OwnerUserID, Phase: result.Phase,
	}
	if includePAT && result.PersonalAccessToken != "" {
		response.PersonalAccessToken = &result.PersonalAccessToken
	}
	return response
}
