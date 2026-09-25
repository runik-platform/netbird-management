package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const runikOwnerName = "operator-owner"

type runikBootstrapStore interface {
	LockRunikBootstrap(ctx context.Context, instanceID string) error
	GetRunikBootstrapState(ctx context.Context, instanceID string) (*types.RunikBootstrapState, error)
	SaveRunikBootstrapState(ctx context.Context, state *types.RunikBootstrapState) error
}

type RunikBootstrapRequest struct {
	InstanceID  string
	AccountID   string
	AccountName string
}

// RunikBootstrapAdoptionRequest identifies an existing account and the Owner
// authorizing its explicit transfer to the Runik service identity.
type RunikBootstrapAdoptionRequest struct {
	InstanceID      string
	AccountID       string
	AccountName     string
	InitiatorUserID string
}

// RunikOwnerCredentialRequest identifies one declarative credential revision
// for the sealed operator owner.
type RunikOwnerCredentialRequest struct {
	InstanceID      string
	Revision        string
	AccountID       string
	InitiatorUserID string
	PlainPAT        string
}

type RunikBootstrapResult struct {
	InstanceID          string
	AccountID           string
	AccountName         string
	OwnerUserID         string
	Phase               string
	PersonalAccessToken string
}

func runikOwnerID(instanceID string) string {
	sum := sha256.Sum256([]byte(instanceID + ":" + runikOwnerName))
	return "runik-" + hex.EncodeToString(sum[:12])
}

func validateRunikBootstrapRequest(req RunikBootstrapRequest) error {
	if strings.TrimSpace(req.InstanceID) == "" || strings.TrimSpace(req.AccountID) == "" || strings.TrimSpace(req.AccountName) == "" {
		return status.Errorf(status.InvalidArgument, "instance_id, account_id and account_name are required")
	}
	if len(req.InstanceID) > 255 || len(req.AccountID) > 255 || len(req.AccountName) > 255 {
		return status.Errorf(status.InvalidArgument, "bootstrap identifiers must not exceed 255 characters")
	}
	return nil
}

func validateRunikBootstrapAdoptionRequest(req RunikBootstrapAdoptionRequest) error {
	return validateRunikBootstrapRequest(RunikBootstrapRequest{
		InstanceID: req.InstanceID, AccountID: req.AccountID, AccountName: req.AccountName,
	})
}

func validateRunikOwnerCredentialRequest(req RunikOwnerCredentialRequest, requireRevision bool) error {
	if strings.TrimSpace(req.InstanceID) == "" ||
		strings.TrimSpace(req.AccountID) == "" || strings.TrimSpace(req.InitiatorUserID) == "" ||
		strings.TrimSpace(req.PlainPAT) == "" {
		return status.Errorf(status.InvalidArgument, "instance_id and authenticated PAT identity are required")
	}
	if requireRevision && strings.TrimSpace(req.Revision) == "" {
		return status.Errorf(status.InvalidArgument, "credential revision is required")
	}
	if len(req.InstanceID) > 255 || len(req.Revision) > 255 {
		return status.Errorf(status.InvalidArgument, "credential rotation identifiers must not exceed 255 characters")
	}
	return nil
}

func runikRotationPATName(revision string) string {
	sum := sha256.Sum256([]byte(revision))
	return "runik-operator-owner-" + hex.EncodeToString(sum[:6])
}

// AdoptRunikBootstrap explicitly transfers an existing account from its
// authenticated Owner to the deterministic Runik service identity. Existing
// users and data are preserved; former Owners become administrators.
func (am *DefaultAccountManager) AdoptRunikBootstrap(ctx context.Context, req RunikBootstrapAdoptionRequest) (*RunikBootstrapResult, error) {
	if err := validateRunikBootstrapAdoptionRequest(req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.InitiatorUserID) == "" {
		return nil, status.Errorf(status.InvalidArgument, "initiator user ID is required")
	}

	unlock := am.Store.AcquireGlobalLock(ctx)
	defer unlock()

	var result *RunikBootstrapResult
	err := am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		bootstrapStore, ok := tx.(runikBootstrapStore)
		if !ok {
			return status.Errorf(status.PreconditionFailed, "runik bootstrap requires a SQL store")
		}
		if err := bootstrapStore.LockRunikBootstrap(ctx, req.InstanceID); err != nil {
			return fmt.Errorf("lock runik bootstrap: %w", err)
		}

		state, err := bootstrapStore.GetRunikBootstrapState(ctx, req.InstanceID)
		if err != nil {
			return fmt.Errorf("read runik bootstrap state: %w", err)
		}
		ownerID := runikOwnerID(req.InstanceID)
		account, err := tx.GetAccount(ctx, req.AccountID)
		if err != nil {
			return status.Errorf(status.PreconditionFailed, "adoption account is missing: %v", err)
		}
		initiator := account.Users[req.InitiatorUserID]
		if initiator == nil || !initiator.HasAdminPower() {
			return status.Errorf(status.PermissionDenied, "account adoption requires an administrator")
		}

		if state == nil {
			if initiator.Role != types.UserRoleOwner {
				return status.Errorf(status.PermissionDenied, "initial account adoption requires its current Owner")
			}
			if account.Users[ownerID] != nil {
				return status.Errorf(status.PreconditionFailed, "deterministic operator owner already exists without bootstrap state")
			}
			for _, user := range account.Users {
				if user.Role == types.UserRoleOwner {
					user.Role = types.UserRoleAdmin
				}
			}
			owner := types.NewOwnerUser(ownerID, "", runikOwnerName)
			owner.AccountID = req.AccountID
			owner.IsServiceUser = true
			owner.NonDeletable = true
			owner.ServiceUserName = runikOwnerName
			owner.Issued = types.UserIssuedAPI
			account.Users[ownerID] = owner
			if err := tx.SaveAccount(ctx, account); err != nil {
				return fmt.Errorf("adopt runik account: %w", err)
			}
			state = &types.RunikBootstrapState{
				InstanceID: req.InstanceID, AccountID: req.AccountID, AccountName: req.AccountName,
				OwnerUserID: ownerID, Phase: types.RunikBootstrapPhaseBootstrapping,
			}
		} else {
			if state.AccountID != req.AccountID || state.AccountName != req.AccountName || state.OwnerUserID != ownerID {
				return status.Errorf(status.PreconditionFailed, "adoption request conflicts with persisted instance identity")
			}
			if state.Phase == types.RunikBootstrapPhaseSealed {
				return status.Errorf(status.PreconditionFailed, "runik bootstrap is sealed")
			}
			if err := validateAdoptedRunikOwner(account, state); err != nil {
				return err
			}
			if state.ActiveTokenID != "" {
				if err := tx.DeletePAT(ctx, state.OwnerUserID, state.ActiveTokenID); err != nil {
					return fmt.Errorf("revoke unacknowledged bootstrap PAT: %w", err)
				}
			}
		}

		pat, err := types.CreateNewPAT("runik-operator-owner", 1, state.OwnerUserID, state.OwnerUserID)
		if err != nil {
			return fmt.Errorf("generate runik owner PAT: %w", err)
		}
		pat.ExpirationDate = nil
		if err := tx.SavePAT(ctx, &pat.PersonalAccessToken); err != nil {
			return fmt.Errorf("save runik owner PAT: %w", err)
		}
		state.ActiveTokenID = pat.ID
		state.Phase = types.RunikBootstrapPhaseBootstrapping
		if err := bootstrapStore.SaveRunikBootstrapState(ctx, state); err != nil {
			return fmt.Errorf("save runik bootstrap state: %w", err)
		}
		result = resultFromRunikState(state)
		result.PersonalAccessToken = pat.PlainToken
		return nil
	})
	return result, err
}

func validateAdoptedRunikOwner(account *types.Account, state *types.RunikBootstrapState) error {
	owner := account.Users[state.OwnerUserID]
	if owner == nil || owner.Role != types.UserRoleOwner || !owner.IsServiceUser || !owner.NonDeletable || owner.ServiceUserName != runikOwnerName || owner.Issued != types.UserIssuedAPI {
		return status.Errorf(status.PreconditionFailed, "adopted operator owner is incompatible")
	}
	for userID, user := range account.Users {
		if userID != state.OwnerUserID && user.Role == types.UserRoleOwner {
			return status.Errorf(status.PreconditionFailed, "adopted account contains another Owner")
		}
	}
	return nil
}

// RunikBootstrap creates or resumes the declarative one-shot bootstrap. A
// retry before acknowledgement replaces the unacknowledged PAT atomically, so
// a caller that lost the response can always recover without duplicate owners.
func (am *DefaultAccountManager) RunikBootstrap(ctx context.Context, req RunikBootstrapRequest) (*RunikBootstrapResult, error) {
	if err := validateRunikBootstrapRequest(req); err != nil {
		return nil, err
	}

	unlock := am.Store.AcquireGlobalLock(ctx)
	defer unlock()

	var result *RunikBootstrapResult
	err := am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		bootstrapStore, ok := tx.(runikBootstrapStore)
		if !ok {
			return status.Errorf(status.PreconditionFailed, "runik bootstrap requires a SQL store")
		}
		if err := bootstrapStore.LockRunikBootstrap(ctx, req.InstanceID); err != nil {
			return fmt.Errorf("lock runik bootstrap: %w", err)
		}

		state, err := bootstrapStore.GetRunikBootstrapState(ctx, req.InstanceID)
		if err != nil {
			return fmt.Errorf("read runik bootstrap state: %w", err)
		}
		ownerID := runikOwnerID(req.InstanceID)
		if state == nil {
			count, err := tx.GetAccountsCounter(ctx)
			if err != nil {
				return fmt.Errorf("count accounts: %w", err)
			}
			if count != 0 {
				return status.Errorf(status.PreconditionFailed, "an account already exists without matching runik bootstrap state")
			}

			account := newAccountWithId(ctx, req.AccountID, ownerID, "", "", runikOwnerName, am.disableDefaultPolicy)
			owner := account.Users[ownerID]
			owner.IsServiceUser = true
			owner.NonDeletable = true
			owner.ServiceUserName = runikOwnerName
			owner.Issued = types.UserIssuedAPI
			owner.Email = ""
			owner.Name = runikOwnerName
			if err := tx.SaveAccount(ctx, account); err != nil {
				return fmt.Errorf("create runik account: %w", err)
			}

			state = &types.RunikBootstrapState{
				InstanceID:  req.InstanceID,
				AccountID:   req.AccountID,
				AccountName: req.AccountName,
				OwnerUserID: ownerID,
				Phase:       types.RunikBootstrapPhaseBootstrapping,
			}
		} else {
			if state.AccountID != req.AccountID || state.AccountName != req.AccountName || state.OwnerUserID != ownerID {
				return status.Errorf(status.PreconditionFailed, "bootstrap request conflicts with persisted instance identity")
			}
			if state.Phase == types.RunikBootstrapPhaseSealed {
				return status.Errorf(status.PreconditionFailed, "runik bootstrap is sealed")
			}
			if err := validateRunikOwner(ctx, tx, state); err != nil {
				return err
			}
			if state.ActiveTokenID != "" {
				if err := tx.DeletePAT(ctx, state.OwnerUserID, state.ActiveTokenID); err != nil {
					return fmt.Errorf("revoke unacknowledged bootstrap PAT: %w", err)
				}
			}
		}

		pat, err := types.CreateNewPAT("runik-operator-owner", 1, state.OwnerUserID, state.OwnerUserID)
		if err != nil {
			return fmt.Errorf("generate runik owner PAT: %w", err)
		}
		pat.ExpirationDate = nil
		if err := tx.SavePAT(ctx, &pat.PersonalAccessToken); err != nil {
			return fmt.Errorf("save runik owner PAT: %w", err)
		}
		state.ActiveTokenID = pat.ID
		state.Phase = types.RunikBootstrapPhaseBootstrapping
		if err := bootstrapStore.SaveRunikBootstrapState(ctx, state); err != nil {
			return fmt.Errorf("save runik bootstrap state: %w", err)
		}

		result = resultFromRunikState(state)
		result.PersonalAccessToken = pat.PlainToken
		return nil
	})
	return result, err
}

func validateRunikOwner(ctx context.Context, tx store.Store, state *types.RunikBootstrapState) error {
	account, err := tx.GetAccount(ctx, state.AccountID)
	if err != nil {
		return status.Errorf(status.PreconditionFailed, "bootstrap account is missing: %v", err)
	}
	if len(account.Users) != 1 {
		return status.Errorf(status.PreconditionFailed, "bootstrap account has incompatible users")
	}
	owner := account.Users[state.OwnerUserID]
	if owner == nil || owner.Role != types.UserRoleOwner || !owner.IsServiceUser || !owner.NonDeletable || owner.ServiceUserName != runikOwnerName || owner.Issued != types.UserIssuedAPI {
		return status.Errorf(status.PreconditionFailed, "bootstrap owner is incompatible")
	}
	return nil
}

func resultFromRunikState(state *types.RunikBootstrapState) *RunikBootstrapResult {
	return &RunikBootstrapResult{
		InstanceID:  state.InstanceID,
		AccountID:   state.AccountID,
		AccountName: state.AccountName,
		OwnerUserID: state.OwnerUserID,
		Phase:       state.Phase,
	}
}

func (am *DefaultAccountManager) GetRunikBootstrapStatus(ctx context.Context, instanceID string) (*RunikBootstrapResult, error) {
	if strings.TrimSpace(instanceID) == "" {
		return nil, status.Errorf(status.InvalidArgument, "instance_id is required")
	}
	bootstrapStore, ok := am.Store.(runikBootstrapStore)
	if !ok {
		return nil, status.Errorf(status.PreconditionFailed, "runik bootstrap requires a SQL store")
	}
	state, err := bootstrapStore.GetRunikBootstrapState(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return &RunikBootstrapResult{InstanceID: instanceID, Phase: "pending"}, nil
	}
	return resultFromRunikState(state), nil
}

func (am *DefaultAccountManager) SealRunikBootstrap(ctx context.Context, instanceID, accountID, userID, plainPAT string) (*RunikBootstrapResult, error) {
	if strings.TrimSpace(instanceID) == "" || strings.TrimSpace(accountID) == "" || strings.TrimSpace(userID) == "" || strings.TrimSpace(plainPAT) == "" {
		return nil, status.Errorf(status.InvalidArgument, "instance_id and authenticated PAT identity are required")
	}

	unlock := am.Store.AcquireGlobalLock(ctx)
	defer unlock()

	var result *RunikBootstrapResult
	err := am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		bootstrapStore, ok := tx.(runikBootstrapStore)
		if !ok {
			return status.Errorf(status.PreconditionFailed, "runik bootstrap requires a SQL store")
		}
		if err := bootstrapStore.LockRunikBootstrap(ctx, instanceID); err != nil {
			return fmt.Errorf("lock runik bootstrap: %w", err)
		}
		state, err := bootstrapStore.GetRunikBootstrapState(ctx, instanceID)
		if err != nil {
			return err
		}
		if state == nil {
			return status.Errorf(status.PreconditionFailed, "runik bootstrap has not started")
		}
		if state.AccountID != accountID || state.OwnerUserID != userID {
			return status.Errorf(status.Unauthorized, "authenticated PAT does not belong to the bootstrap owner")
		}
		if state.Phase == types.RunikBootstrapPhaseSealed {
			return status.Errorf(status.PreconditionFailed, "runik bootstrap is sealed")
		}
		pat, err := tx.GetPATByID(ctx, store.LockingStrengthUpdate, state.OwnerUserID, state.ActiveTokenID)
		if err != nil {
			return status.Errorf(status.PreconditionFailed, "active bootstrap PAT is missing")
		}
		digest := sha256.Sum256([]byte(plainPAT))
		hashed := base64.StdEncoding.EncodeToString(digest[:])
		if subtle.ConstantTimeCompare([]byte(hashed), []byte(pat.HashedToken)) != 1 {
			return status.Errorf(status.Unauthorized, "personal access token does not match active bootstrap token")
		}
		now := time.Now().UTC()
		state.Phase = types.RunikBootstrapPhaseSealed
		state.SealedAt = &now
		if err := bootstrapStore.SaveRunikBootstrapState(ctx, state); err != nil {
			return err
		}
		result = resultFromRunikState(state)
		return nil
	})
	return result, err
}

// VerifyRunikOwnerCredential confirms that the presented PAT is the active
// credential recorded for the sealed operator owner.
func (am *DefaultAccountManager) VerifyRunikOwnerCredential(ctx context.Context, req RunikOwnerCredentialRequest) (*RunikBootstrapResult, error) {
	if err := validateRunikOwnerCredentialRequest(req, false); err != nil {
		return nil, err
	}

	unlock := am.Store.AcquireGlobalLock(ctx)
	defer unlock()

	var result *RunikBootstrapResult
	err := am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		state, err := loadSealedRunikOwner(ctx, tx, req)
		if err != nil {
			return err
		}
		if err := verifyRunikPAT(ctx, tx, state.OwnerUserID, state.ActiveTokenID, req.PlainPAT); err != nil {
			return err
		}
		result = resultFromRunikState(state)
		return nil
	})
	return result, err
}

// PrepareRunikOwnerCredentialRotation creates one replacement PAT while the
// current credential remains valid. Repeating a lost prepare response replaces
// only the unacknowledged PAT for the same revision.
func (am *DefaultAccountManager) PrepareRunikOwnerCredentialRotation(ctx context.Context, req RunikOwnerCredentialRequest) (*RunikBootstrapResult, error) {
	if err := validateRunikOwnerCredentialRequest(req, true); err != nil {
		return nil, err
	}

	unlock := am.Store.AcquireGlobalLock(ctx)
	defer unlock()

	var result *RunikBootstrapResult
	err := am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		state, err := loadSealedRunikOwner(ctx, tx, req)
		if err != nil {
			return err
		}
		if err := verifyRunikPAT(ctx, tx, state.OwnerUserID, state.ActiveTokenID, req.PlainPAT); err != nil {
			return err
		}

		tokenName := runikRotationPATName(req.Revision)
		active, err := tx.GetPATByID(ctx, store.LockingStrengthUpdate, state.OwnerUserID, state.ActiveTokenID)
		if err != nil {
			return status.Errorf(status.PreconditionFailed, "active operator owner PAT is missing")
		}
		result = resultFromRunikState(state)
		if active.Name == tokenName {
			return nil
		}

		pats, err := tx.GetUserPATs(ctx, store.LockingStrengthUpdate, state.OwnerUserID)
		if err != nil {
			return fmt.Errorf("list operator owner PATs: %w", err)
		}
		for _, pat := range pats {
			if pat.Name == tokenName && pat.ID != state.ActiveTokenID {
				if err := tx.DeletePAT(ctx, state.OwnerUserID, pat.ID); err != nil {
					return fmt.Errorf("remove stale replacement PAT: %w", err)
				}
			}
		}

		pat, err := types.CreateNewPAT(tokenName, 1, state.OwnerUserID, state.OwnerUserID)
		if err != nil {
			return fmt.Errorf("generate replacement operator owner PAT: %w", err)
		}
		pat.ExpirationDate = nil
		if err := tx.SavePAT(ctx, &pat.PersonalAccessToken); err != nil {
			return fmt.Errorf("save replacement operator owner PAT: %w", err)
		}
		result.PersonalAccessToken = pat.PlainToken
		return nil
	})
	return result, err
}

// CompleteRunikOwnerCredentialRotation verifies the replacement PAT and then
// revokes every other credential owned by the service identity.
func (am *DefaultAccountManager) CompleteRunikOwnerCredentialRotation(ctx context.Context, req RunikOwnerCredentialRequest) (*RunikBootstrapResult, error) {
	if err := validateRunikOwnerCredentialRequest(req, true); err != nil {
		return nil, err
	}

	unlock := am.Store.AcquireGlobalLock(ctx)
	defer unlock()

	var result *RunikBootstrapResult
	err := am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		state, err := loadSealedRunikOwner(ctx, tx, req)
		if err != nil {
			return err
		}
		tokenName := runikRotationPATName(req.Revision)
		pats, err := tx.GetUserPATs(ctx, store.LockingStrengthUpdate, state.OwnerUserID)
		if err != nil {
			return fmt.Errorf("list operator owner PATs: %w", err)
		}
		var replacement *types.PersonalAccessToken
		for _, pat := range pats {
			if pat.Name == tokenName {
				if replacement != nil {
					return status.Errorf(status.PreconditionFailed, "credential revision has duplicate replacement PATs")
				}
				replacement = pat
			}
		}
		if replacement == nil {
			return status.Errorf(status.PreconditionFailed, "replacement operator owner PAT is missing")
		}
		if err := verifyRunikPAT(ctx, tx, state.OwnerUserID, replacement.ID, req.PlainPAT); err != nil {
			return err
		}
		for _, pat := range pats {
			if pat.ID != replacement.ID {
				if err := tx.DeletePAT(ctx, state.OwnerUserID, pat.ID); err != nil {
					return fmt.Errorf("revoke superseded operator owner PAT: %w", err)
				}
			}
		}
		state.ActiveTokenID = replacement.ID
		if bootstrapStore, ok := tx.(runikBootstrapStore); ok {
			if err := bootstrapStore.SaveRunikBootstrapState(ctx, state); err != nil {
				return fmt.Errorf("save active operator owner PAT: %w", err)
			}
		} else {
			return status.Errorf(status.PreconditionFailed, "runik bootstrap requires a SQL store")
		}
		result = resultFromRunikState(state)
		return nil
	})
	return result, err
}

func loadSealedRunikOwner(ctx context.Context, tx store.Store, req RunikOwnerCredentialRequest) (*types.RunikBootstrapState, error) {
	bootstrapStore, ok := tx.(runikBootstrapStore)
	if !ok {
		return nil, status.Errorf(status.PreconditionFailed, "runik bootstrap requires a SQL store")
	}
	if err := bootstrapStore.LockRunikBootstrap(ctx, req.InstanceID); err != nil {
		return nil, fmt.Errorf("lock runik bootstrap: %w", err)
	}
	state, err := bootstrapStore.GetRunikBootstrapState(ctx, req.InstanceID)
	if err != nil {
		return nil, fmt.Errorf("read runik bootstrap state: %w", err)
	}
	if state == nil || state.Phase != types.RunikBootstrapPhaseSealed {
		return nil, status.Errorf(status.PreconditionFailed, "runik bootstrap is not sealed")
	}
	if state.AccountID != req.AccountID || state.OwnerUserID != req.InitiatorUserID {
		return nil, status.Errorf(status.Unauthorized, "authenticated PAT does not belong to the operator owner")
	}
	account, err := tx.GetAccount(ctx, state.AccountID)
	if err != nil {
		return nil, status.Errorf(status.PreconditionFailed, "bootstrap account is missing: %v", err)
	}
	if err := validateAdoptedRunikOwner(account, state); err != nil {
		return nil, err
	}
	return state, nil
}

func verifyRunikPAT(ctx context.Context, tx store.Store, ownerUserID, tokenID, plainPAT string) error {
	pat, err := tx.GetPATByID(ctx, store.LockingStrengthUpdate, ownerUserID, tokenID)
	if err != nil {
		return status.Errorf(status.PreconditionFailed, "active operator owner PAT is missing")
	}
	digest := sha256.Sum256([]byte(plainPAT))
	hashed := base64.StdEncoding.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(hashed), []byte(pat.HashedToken)) != 1 {
		return status.Errorf(status.Unauthorized, "personal access token does not match operator owner credential")
	}
	return nil
}
