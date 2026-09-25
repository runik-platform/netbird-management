package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type runikIdentityStore interface {
	LockRunikIdentitySource(ctx context.Context, accountID, source string) error
	GetRunikIdentitySource(ctx context.Context, accountID, source string) (*types.RunikIdentitySource, error)
	SaveRunikIdentitySource(ctx context.Context, state *types.RunikIdentitySource) error
	GetRunikIdentityUsers(ctx context.Context, accountID, source string) ([]*types.RunikIdentityUser, error)
	GetRunikIdentityUserByUserID(ctx context.Context, userID string) (*types.RunikIdentityUser, error)
	SaveRunikIdentityUser(ctx context.Context, mapping *types.RunikIdentityUser) error
	GetRunikIdentityGroups(ctx context.Context, accountID, source string) ([]*types.RunikIdentityGroup, error)
	GetRunikIdentityGroupByGroupID(ctx context.Context, groupID string) (*types.RunikIdentityGroup, error)
	SaveRunikIdentityGroup(ctx context.Context, mapping *types.RunikIdentityGroup) error
}

type RunikExternalUser struct {
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	AdoptExisting bool   `json:"adopt_existing,omitempty"`
}

type RunikExternalGroup struct {
	ExternalID    string `json:"external_id"`
	Name          string `json:"name"`
	AdoptExisting bool   `json:"adopt_existing,omitempty"`
}

type RunikExternalMembership struct {
	Issuer           string   `json:"issuer"`
	Subject          string   `json:"subject"`
	GroupExternalIDs []string `json:"group_external_ids"`
}

type RunikIdentitySyncRequest struct {
	InstanceID  string                    `json:"instance_id"`
	Source      string                    `json:"source"`
	Revision    string                    `json:"revision"`
	Complete    bool                      `json:"complete"`
	Users       []RunikExternalUser       `json:"users"`
	Groups      []RunikExternalGroup      `json:"groups"`
	Memberships []RunikExternalMembership `json:"memberships"`
}

type RunikIdentityObjectResult struct {
	ExternalID string `json:"external_id"`
	InternalID string `json:"internal_id"`
	Action     string `json:"action"`
}

type RunikIdentitySyncResult struct {
	AccountID   string                      `json:"account_id"`
	Source      string                      `json:"source"`
	Revision    string                      `json:"revision"`
	Changed     bool                        `json:"changed"`
	Users       []RunikIdentityObjectResult `json:"users"`
	Groups      []RunikIdentityObjectResult `json:"groups"`
	Memberships []RunikIdentityObjectResult `json:"memberships"`
}

type runikIdentityEvent struct {
	targetID string
	action   activity.Activity
	meta     map[string]any
}

func runikUserExternalID(issuer, subject string) string {
	return issuer + "#" + subject
}

func runikUserKey(issuer, subject string) string {
	return fmt.Sprintf("%d:%s%s", len(issuer), issuer, subject)
}

func runikGroupID(accountID, source, externalID string) string {
	sum := sha256.Sum256([]byte(accountID + "\x00" + source + "\x00" + externalID))
	return "runik-" + hex.EncodeToString(sum[:16])
}

func runikIdentityMappingID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func cloneRunikIdentityRequest(req RunikIdentitySyncRequest) RunikIdentitySyncRequest {
	req.Users = append([]RunikExternalUser(nil), req.Users...)
	req.Groups = append([]RunikExternalGroup(nil), req.Groups...)
	req.Memberships = append([]RunikExternalMembership(nil), req.Memberships...)
	for i := range req.Memberships {
		req.Memberships[i].GroupExternalIDs = append(
			[]string(nil), req.Memberships[i].GroupExternalIDs...,
		)
	}
	return req
}

func canonicalRunikIdentitySnapshot(req RunikIdentitySyncRequest) (string, error) {
	if req.Users == nil {
		req.Users = []RunikExternalUser{}
	}
	if req.Groups == nil {
		req.Groups = []RunikExternalGroup{}
	}
	if req.Memberships == nil {
		req.Memberships = []RunikExternalMembership{}
	}
	sort.Slice(req.Users, func(i, j int) bool {
		return runikUserKey(req.Users[i].Issuer, req.Users[i].Subject) < runikUserKey(req.Users[j].Issuer, req.Users[j].Subject)
	})
	sort.Slice(req.Groups, func(i, j int) bool { return req.Groups[i].ExternalID < req.Groups[j].ExternalID })
	for i := range req.Memberships {
		if req.Memberships[i].GroupExternalIDs == nil {
			req.Memberships[i].GroupExternalIDs = []string{}
		}
		sort.Strings(req.Memberships[i].GroupExternalIDs)
	}
	sort.Slice(req.Memberships, func(i, j int) bool {
		return runikUserKey(req.Memberships[i].Issuer, req.Memberships[i].Subject) < runikUserKey(req.Memberships[j].Issuer, req.Memberships[j].Subject)
	})
	payload, err := json.Marshal(struct {
		Users       []RunikExternalUser       `json:"users"`
		Groups      []RunikExternalGroup      `json:"groups"`
		Memberships []RunikExternalMembership `json:"memberships"`
	}{req.Users, req.Groups, req.Memberships})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func validateRunikIdentityRequest(req *RunikIdentitySyncRequest) error {
	req.InstanceID = strings.TrimSpace(req.InstanceID)
	req.Source = strings.TrimSpace(req.Source)
	req.Revision = strings.TrimSpace(req.Revision)
	if req.InstanceID == "" || req.Source == "" || req.Revision == "" {
		return status.Errorf(status.InvalidArgument, "instance_id, source, and revision are required")
	}
	if len(req.InstanceID) > 255 || len(req.Source) > 255 || len(req.Revision) > 255 {
		return status.Errorf(status.InvalidArgument, "instance_id, source, and revision must not exceed 255 bytes")
	}
	if !req.Complete {
		return status.Errorf(status.InvalidArgument, "only complete authoritative snapshots are accepted")
	}

	users := make(map[string]struct{}, len(req.Users))
	for i := range req.Users {
		u := &req.Users[i]
		u.Issuer, u.Subject = strings.TrimSpace(u.Issuer), strings.TrimSpace(u.Subject)
		if u.Issuer == "" || u.Subject == "" {
			return status.Errorf(status.InvalidArgument, "every user requires issuer and subject")
		}
		if len(u.Subject) > 255 {
			return status.Errorf(status.InvalidArgument, "user subject must not exceed 255 bytes")
		}
		key := runikUserKey(u.Issuer, u.Subject)
		if _, exists := users[key]; exists {
			return status.Errorf(status.InvalidArgument, "duplicate user identity %q", runikUserExternalID(u.Issuer, u.Subject))
		}
		users[key] = struct{}{}
	}

	groups := make(map[string]string, len(req.Groups))
	names := make(map[string]string, len(req.Groups))
	for i := range req.Groups {
		g := &req.Groups[i]
		g.ExternalID, g.Name = strings.TrimSpace(g.ExternalID), strings.TrimSpace(g.Name)
		if g.ExternalID == "" || g.Name == "" {
			return status.Errorf(status.InvalidArgument, "every group requires external_id and name")
		}
		if g.Name == types.GroupAllName {
			return status.Errorf(status.InvalidArgument, "the reserved All group cannot be reconciled")
		}
		if _, exists := groups[g.ExternalID]; exists {
			return status.Errorf(status.InvalidArgument, "duplicate group external ID %q", g.ExternalID)
		}
		nameKey := strings.ToLower(g.Name)
		if other, exists := names[nameKey]; exists {
			return status.Errorf(status.InvalidArgument, "groups %q and %q have the same name", other, g.ExternalID)
		}
		groups[g.ExternalID] = g.Name
		names[nameKey] = g.ExternalID
	}

	memberships := make(map[string]struct{}, len(req.Memberships))
	for i := range req.Memberships {
		m := &req.Memberships[i]
		m.Issuer, m.Subject = strings.TrimSpace(m.Issuer), strings.TrimSpace(m.Subject)
		key := runikUserKey(m.Issuer, m.Subject)
		if _, exists := users[key]; !exists {
			return status.Errorf(status.InvalidArgument, "membership references unknown user %q", runikUserExternalID(m.Issuer, m.Subject))
		}
		if _, exists := memberships[key]; exists {
			return status.Errorf(status.InvalidArgument, "duplicate membership entry for user %q", runikUserExternalID(m.Issuer, m.Subject))
		}
		memberships[key] = struct{}{}
		seenGroups := make(map[string]struct{}, len(m.GroupExternalIDs))
		for j := range m.GroupExternalIDs {
			m.GroupExternalIDs[j] = strings.TrimSpace(m.GroupExternalIDs[j])
			if _, exists := groups[m.GroupExternalIDs[j]]; !exists {
				return status.Errorf(status.InvalidArgument, "membership for %q references unknown group %q", runikUserExternalID(m.Issuer, m.Subject), m.GroupExternalIDs[j])
			}
			if _, exists := seenGroups[m.GroupExternalIDs[j]]; exists {
				return status.Errorf(status.InvalidArgument, "membership for %q repeats group %q", runikUserExternalID(m.Issuer, m.Subject), m.GroupExternalIDs[j])
			}
			seenGroups[m.GroupExternalIDs[j]] = struct{}{}
		}
	}
	return nil
}

// ReconcileRunikIdentities applies one complete external-source snapshot. The
// bootstrap owner is the only identity authorized to call this primitive.
func (am *DefaultAccountManager) ReconcileRunikIdentities(ctx context.Context, accountID, initiatorUserID string, req RunikIdentitySyncRequest) (*RunikIdentitySyncResult, error) {
	// Validation normalizes strings and canonicalization sorts slices. Clone the
	// caller-owned snapshot before either step so concurrent retries can safely
	// reuse the same request value.
	req = cloneRunikIdentityRequest(req)
	if err := validateRunikIdentityRequest(&req); err != nil {
		return nil, err
	}
	snapshotHash, err := canonicalRunikIdentitySnapshot(req)
	if err != nil {
		return nil, status.Errorf(status.InvalidArgument, "invalid identity snapshot")
	}

	unlock := am.Store.AcquireGlobalLock(ctx)
	defer unlock()

	result := &RunikIdentitySyncResult{
		AccountID:   accountID,
		Source:      req.Source,
		Revision:    req.Revision,
		Users:       []RunikIdentityObjectResult{},
		Groups:      []RunikIdentityObjectResult{},
		Memberships: []RunikIdentityObjectResult{},
	}
	var events []runikIdentityEvent
	var usersChanged, networkChanged bool
	err = am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		identityStore, ok := tx.(runikIdentityStore)
		if !ok {
			return status.Errorf(status.PreconditionFailed, "runik identity reconciliation requires a SQL store")
		}
		if err := identityStore.LockRunikIdentitySource(ctx, accountID, req.Source); err != nil {
			return fmt.Errorf("lock runik identity source: %w", err)
		}
		if err := authorizeRunikIdentitySync(ctx, tx, req.InstanceID, accountID, initiatorUserID); err != nil {
			return err
		}

		state, err := identityStore.GetRunikIdentitySource(ctx, accountID, req.Source)
		if err != nil {
			return fmt.Errorf("read runik identity source: %w", err)
		}
		if state != nil {
			if state.InstanceID != req.InstanceID {
				return status.Errorf(status.PreconditionFailed, "identity source belongs to another Runik instance")
			}
			if state.Revision == req.Revision && state.SnapshotHash != snapshotHash {
				return status.Errorf(status.PreconditionFailed, "revision %q was already used by a different snapshot", req.Revision)
			}
		}

		groupMappings, err := identityStore.GetRunikIdentityGroups(ctx, accountID, req.Source)
		if err != nil {
			return fmt.Errorf("read runik group mappings: %w", err)
		}
		groupMappingByExternal := make(map[string]*types.RunikIdentityGroup, len(groupMappings))
		ownedGroupIDs := make(map[string]struct{}, len(groupMappings)+len(req.Groups))
		for _, mapping := range groupMappings {
			groupMappingByExternal[mapping.ExternalID] = mapping
			ownedGroupIDs[mapping.GroupID] = struct{}{}
		}
		accountGroups, err := tx.GetAccountGroups(ctx, store.LockingStrengthUpdate, accountID)
		if err != nil {
			return fmt.Errorf("read account groups: %w", err)
		}
		groupsByID := make(map[string]*types.Group, len(accountGroups))
		groupsByName := make(map[string][]*types.Group, len(accountGroups))
		for _, group := range accountGroups {
			groupsByID[group.ID] = group
			key := strings.ToLower(group.Name)
			groupsByName[key] = append(groupsByName[key], group)
		}

		resolvedGroups := make(map[string]string, len(req.Groups))
		requestedGroups := make(map[string]struct{}, len(req.Groups))
		for _, external := range req.Groups {
			requestedGroups[external.ExternalID] = struct{}{}
			mapping := groupMappingByExternal[external.ExternalID]
			action := "unchanged"
			if mapping == nil {
				groupID := runikGroupID(accountID, req.Source, external.ExternalID)
				if existingMapping, err := identityStore.GetRunikIdentityGroupByGroupID(ctx, groupID); err != nil {
					return err
				} else if existingMapping != nil {
					return status.Errorf(status.PreconditionFailed, "group ID collision for external group %q", external.ExternalID)
				}
				matches := groupsByName[strings.ToLower(external.Name)]
				switch {
				case len(matches) == 0:
					if groupsByID[groupID] != nil {
						return status.Errorf(status.PreconditionFailed, "internal group ID collision for external group %q", external.ExternalID)
					}
					group := &types.Group{ID: groupID, AccountID: accountID, PublicID: xid.New().String(), Name: external.Name, Issued: types.GroupIssuedIntegration, Resources: []types.Resource{}}
					if err := tx.CreateGroup(ctx, group); err != nil {
						return fmt.Errorf("create group %q: %w", external.ExternalID, err)
					}
					groupsByID[groupID] = group
					nameKey := strings.ToLower(group.Name)
					groupsByName[nameKey] = append(groupsByName[nameKey], group)
					action = "created"
					events = append(events, runikIdentityEvent{group.ID, activity.RunikIdentityReconciled, map[string]any{"source": req.Source, "external_id": external.ExternalID, "kind": "group", "action": action}})
				case len(matches) > 0 && external.AdoptExisting:
					for _, match := range matches {
						if match.Issued != types.GroupIssuedJWT {
							return status.Errorf(status.PreconditionFailed, "group name %q collides with an unmanaged group", external.Name)
						}
					}
					sort.Slice(matches, func(i, j int) bool { return matches[i].ID < matches[j].ID })
					groupID = matches[0].ID
					if existingMapping, err := identityStore.GetRunikIdentityGroupByGroupID(ctx, groupID); err != nil {
						return err
					} else if existingMapping != nil {
						return status.Errorf(status.PreconditionFailed, "group %q is owned by another identity source", external.Name)
					}
					matches[0].Issued = types.GroupIssuedIntegration
					if err := tx.UpdateGroup(ctx, matches[0]); err != nil {
						return fmt.Errorf("adopt group %q: %w", external.ExternalID, err)
					}
					for _, match := range matches {
						ownedGroupIDs[match.ID] = struct{}{}
					}
					action = "adopted"
					events = append(events, runikIdentityEvent{groupID, activity.RunikIdentityReconciled, map[string]any{"source": req.Source, "external_id": external.ExternalID, "kind": "group", "action": action}})
				default:
					return status.Errorf(status.PreconditionFailed, "group name %q collides with an unmanaged group", external.Name)
				}
				mapping = &types.RunikIdentityGroup{AccountID: accountID, Source: req.Source, ExternalID: external.ExternalID, GroupID: groupID}
				mapping.ID = runikIdentityMappingID("group", accountID, req.Source, external.ExternalID)
				if err := identityStore.SaveRunikIdentityGroup(ctx, mapping); err != nil {
					return fmt.Errorf("save group identity %q: %w", external.ExternalID, err)
				}
				groupMappingByExternal[external.ExternalID] = mapping
				ownedGroupIDs[groupID] = struct{}{}
			} else {
				group := groupsByID[mapping.GroupID]
				if group == nil {
					return status.Errorf(status.PreconditionFailed, "managed group %q is missing", external.ExternalID)
				}
				for _, colliding := range groupsByName[strings.ToLower(external.Name)] {
					if colliding.ID == group.ID {
						continue
					}
					if colliding.Issued != types.GroupIssuedJWT {
						return status.Errorf(status.PreconditionFailed, "group rename to %q collides with another group", external.Name)
					}
					ownedGroupIDs[colliding.ID] = struct{}{}
				}
				if group.Name != external.Name {
					oldNameKey := strings.ToLower(group.Name)
					groupsByName[oldNameKey] = removeRunikGroup(groupsByName[oldNameKey], group.ID)
					group.Name = external.Name
					group.Issued = types.GroupIssuedIntegration
					if err := tx.UpdateGroup(ctx, group); err != nil {
						return fmt.Errorf("rename group %q: %w", external.ExternalID, err)
					}
					nameKey := strings.ToLower(group.Name)
					groupsByName[nameKey] = append(groupsByName[nameKey], group)
					action = "renamed"
					events = append(events, runikIdentityEvent{group.ID, activity.RunikIdentityReconciled, map[string]any{"source": req.Source, "external_id": external.ExternalID, "kind": "group", "action": action}})
				}
			}
			resolvedGroups[external.ExternalID] = mapping.GroupID
			result.Groups = append(result.Groups, RunikIdentityObjectResult{ExternalID: external.ExternalID, InternalID: mapping.GroupID, Action: action})
			result.Changed = result.Changed || action != "unchanged"
		}
		for _, mapping := range groupMappings {
			if _, exists := requestedGroups[mapping.ExternalID]; !exists {
				result.Groups = append(result.Groups, RunikIdentityObjectResult{ExternalID: mapping.ExternalID, InternalID: mapping.GroupID, Action: "retained"})
			}
		}

		userMappings, err := identityStore.GetRunikIdentityUsers(ctx, accountID, req.Source)
		if err != nil {
			return fmt.Errorf("read runik user mappings: %w", err)
		}
		userMappingByExternal := make(map[string]*types.RunikIdentityUser, len(userMappings))
		for _, mapping := range userMappings {
			userMappingByExternal[runikUserKey(mapping.Issuer, mapping.Subject)] = mapping
		}
		accountUsers, err := tx.GetAccountUsers(ctx, store.LockingStrengthUpdate, accountID)
		if err != nil {
			return fmt.Errorf("read account users: %w", err)
		}
		usersByID := make(map[string]*types.User, len(accountUsers))
		for _, user := range accountUsers {
			usersByID[user.Id] = user
		}
		memberships := make(map[string][]string, len(req.Memberships))
		for _, membership := range req.Memberships {
			memberships[runikUserKey(membership.Issuer, membership.Subject)] = membership.GroupExternalIDs
		}
		requestedUsers := make(map[string]struct{}, len(req.Users))
		settings, err := tx.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			return fmt.Errorf("read account settings: %w", err)
		}

		for _, external := range req.Users {
			externalID := runikUserExternalID(external.Issuer, external.Subject)
			key := runikUserKey(external.Issuer, external.Subject)
			requestedUsers[key] = struct{}{}
			mapping := userMappingByExternal[key]
			action := "unchanged"
			if mapping == nil {
				userID := external.Subject
				if existingMapping, err := identityStore.GetRunikIdentityUserByUserID(ctx, userID); err != nil {
					return err
				} else if existingMapping != nil {
					return status.Errorf(status.PreconditionFailed, "user ID collision for external identity %q", externalID)
				}
				existing, err := tx.GetUserByUserID(ctx, store.LockingStrengthUpdate, userID)
				if err != nil {
					if sErr, ok := status.FromError(err); !ok || sErr.Type() != status.NotFound {
						return fmt.Errorf("check existing user %q: %w", userID, err)
					}
					existing = nil
				}
				switch {
				case existing == nil:
					existing = types.NewRegularUser(userID, external.Email, external.Name)
					existing.AccountID = accountID
					usersByID[userID] = existing
					action = "created"
				case external.AdoptExisting && existing.AccountID == accountID && !existing.IsServiceUser:
					action = "adopted"
				default:
					return status.Errorf(status.PreconditionFailed, "user %q already exists and was not explicitly adopted", userID)
				}
				mapping = &types.RunikIdentityUser{ID: runikIdentityMappingID("user", accountID, req.Source, external.Issuer, external.Subject), AccountID: accountID, Source: req.Source, Issuer: external.Issuer, Subject: external.Subject, UserID: userID}
				if err := identityStore.SaveRunikIdentityUser(ctx, mapping); err != nil {
					return fmt.Errorf("save user identity %q: %w", externalID, err)
				}
				userMappingByExternal[key] = mapping
			}

			user := usersByID[mapping.UserID]
			if user == nil || user.AccountID != accountID || user.IsServiceUser {
				return status.Errorf(status.PreconditionFailed, "managed user %q is missing or incompatible", externalID)
			}
			desiredGroups := make([]string, 0, len(user.AutoGroups)+len(memberships[externalID]))
			for _, groupID := range user.AutoGroups {
				if _, owned := ownedGroupIDs[groupID]; !owned {
					desiredGroups = append(desiredGroups, groupID)
				}
			}
			for _, externalGroupID := range memberships[key] {
				desiredGroups = append(desiredGroups, resolvedGroups[externalGroupID])
			}
			sort.Strings(desiredGroups)
			oldGroups := slices.Clone(user.AutoGroups)
			sort.Strings(oldGroups)
			membershipChanged := !slices.Equal(oldGroups, desiredGroups)
			profileChanged := user.Email != external.Email || user.Name != external.Name
			blockedChanged := user.Blocked
			if action == "unchanged" && (membershipChanged || profileChanged || blockedChanged) {
				action = "updated"
			}
			user.Email, user.Name, user.Blocked, user.AutoGroups = external.Email, external.Name, false, desiredGroups
			if action != "unchanged" {
				if settings != nil && settings.GroupsPropagationEnabled && membershipChanged {
					if err := reconcileRunikPeerGroups(ctx, tx, accountID, user.Id, oldGroups, desiredGroups); err != nil {
						return err
					}
				}
				if err := tx.SaveUser(ctx, user); err != nil {
					return fmt.Errorf("save managed user %q: %w", externalID, err)
				}
				usersChanged = true
				networkChanged = networkChanged || membershipChanged || blockedChanged || action == "created"
				events = append(events, runikIdentityEvent{user.Id, activity.RunikIdentityReconciled, map[string]any{"source": req.Source, "external_id": externalID, "kind": "user", "action": action}})
			}
			membershipAction := "unchanged"
			if membershipChanged {
				membershipAction = "updated"
			}
			result.Users = append(result.Users, RunikIdentityObjectResult{ExternalID: externalID, InternalID: user.Id, Action: action})
			result.Memberships = append(result.Memberships, RunikIdentityObjectResult{ExternalID: externalID, InternalID: user.Id, Action: membershipAction})
			result.Changed = result.Changed || action != "unchanged"
		}

		for _, mapping := range userMappings {
			externalID := runikUserExternalID(mapping.Issuer, mapping.Subject)
			if _, exists := requestedUsers[runikUserKey(mapping.Issuer, mapping.Subject)]; exists {
				continue
			}
			user := usersByID[mapping.UserID]
			if user == nil || user.AccountID != accountID || user.IsServiceUser {
				return status.Errorf(status.PreconditionFailed, "managed user %q is missing or incompatible", externalID)
			}
			oldGroups := slices.Clone(user.AutoGroups)
			desiredGroups := user.AutoGroups[:0]
			for _, groupID := range user.AutoGroups {
				if _, owned := ownedGroupIDs[groupID]; !owned {
					desiredGroups = append(desiredGroups, groupID)
				}
			}
			action := "unchanged"
			membershipChanged := len(oldGroups) != len(desiredGroups)
			if !user.Blocked || membershipChanged {
				user.Blocked = true
				user.AutoGroups = desiredGroups
				if settings != nil && settings.GroupsPropagationEnabled && membershipChanged {
					if err := reconcileRunikPeerGroups(ctx, tx, accountID, user.Id, oldGroups, desiredGroups); err != nil {
						return err
					}
				}
				if err := tx.SaveUser(ctx, user); err != nil {
					return fmt.Errorf("disable absent managed user %q: %w", externalID, err)
				}
				action = "disabled"
				usersChanged, networkChanged = true, true
				events = append(events, runikIdentityEvent{user.Id, activity.RunikIdentityReconciled, map[string]any{"source": req.Source, "external_id": externalID, "kind": "user", "action": action}})
			}
			result.Users = append(result.Users, RunikIdentityObjectResult{ExternalID: externalID, InternalID: user.Id, Action: action})
			result.Memberships = append(result.Memberships, RunikIdentityObjectResult{ExternalID: externalID, InternalID: user.Id, Action: map[bool]string{true: "updated", false: "unchanged"}[membershipChanged]})
			result.Changed = result.Changed || action != "unchanged"
		}

		if networkChanged {
			if err := tx.IncrementNetworkSerial(ctx, accountID); err != nil {
				return fmt.Errorf("increment network serial: %w", err)
			}
		}
		stateChanged := state == nil || state.Revision != req.Revision || state.SnapshotHash != snapshotHash
		if state == nil {
			state = &types.RunikIdentitySource{ID: runikIdentityMappingID("source", accountID, req.Source), AccountID: accountID, Source: req.Source, InstanceID: req.InstanceID}
		}
		if stateChanged {
			state.Revision, state.SnapshotHash = req.Revision, snapshotHash
			if err := identityStore.SaveRunikIdentitySource(ctx, state); err != nil {
				return fmt.Errorf("save runik identity source: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(result.Users, func(i, j int) bool { return result.Users[i].ExternalID < result.Users[j].ExternalID })
	sort.Slice(result.Groups, func(i, j int) bool { return result.Groups[i].ExternalID < result.Groups[j].ExternalID })
	sort.Slice(result.Memberships, func(i, j int) bool { return result.Memberships[i].ExternalID < result.Memberships[j].ExternalID })
	if usersChanged && am.cacheManager != nil {
		if err := am.cacheManager.Delete(ctx, accountID); err != nil {
			log.WithContext(ctx).Warnf("failed to invalidate identity cache for account %s: %v", accountID, err)
		}
	}
	if am.eventStore != nil {
		for _, event := range events {
			am.StoreEvent(ctx, initiatorUserID, event.targetID, accountID, event.action, event.meta)
		}
	}
	if networkChanged && am.networkMapController != nil {
		go am.UpdateAccountPeers(context.WithoutCancel(ctx), accountID, types.UpdateReason{Resource: types.UpdateResourceUser, Operation: types.UpdateOperationUpdate})
	}
	return result, nil
}

func removeRunikGroup(groups []*types.Group, groupID string) []*types.Group {
	for i, group := range groups {
		if group.ID == groupID {
			return append(groups[:i], groups[i+1:]...)
		}
	}
	return groups
}

func authorizeRunikIdentitySync(ctx context.Context, tx store.Store, instanceID, accountID, userID string) error {
	bootstrapStore, ok := tx.(runikBootstrapStore)
	if !ok {
		return status.Errorf(status.PreconditionFailed, "runik identity reconciliation requires bootstrap state")
	}
	state, err := bootstrapStore.GetRunikBootstrapState(ctx, instanceID)
	if err != nil {
		return fmt.Errorf("read runik bootstrap state: %w", err)
	}
	if state == nil || state.Phase != types.RunikBootstrapPhaseSealed || state.AccountID != accountID || state.OwnerUserID != userID {
		return status.Errorf(status.PermissionDenied, "identity reconciliation requires the sealed Runik operator owner")
	}
	user, err := tx.GetUserByUserID(ctx, store.LockingStrengthUpdate, userID)
	if err != nil {
		return status.Errorf(status.PermissionDenied, "identity reconciliation owner is unavailable")
	}
	if user.AccountID != accountID || user.Role != types.UserRoleOwner || !user.IsServiceUser || !user.NonDeletable || user.ServiceUserName != runikOwnerName {
		return status.Errorf(status.PermissionDenied, "identity reconciliation owner is incompatible")
	}
	return nil
}

func reconcileRunikPeerGroups(ctx context.Context, tx store.Store, accountID, userID string, oldGroups, desiredGroups []string) error {
	peers, err := tx.GetUserPeers(ctx, store.LockingStrengthNone, accountID, userID)
	if err != nil {
		return fmt.Errorf("read peers for managed user %q: %w", userID, err)
	}
	for _, peer := range peers {
		for _, groupID := range util.Difference(oldGroups, desiredGroups) {
			if err := tx.RemovePeerFromGroup(ctx, peer.ID, groupID); err != nil {
				return fmt.Errorf("remove peer %q from group %q: %w", peer.ID, groupID, err)
			}
		}
		for _, groupID := range util.Difference(desiredGroups, oldGroups) {
			if err := tx.AddPeerToGroup(ctx, accountID, peer.ID, groupID); err != nil {
				return fmt.Errorf("add peer %q to group %q: %w", peer.ID, groupID, err)
			}
		}
	}
	return nil
}
