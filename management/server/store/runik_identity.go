package store

import (
	"context"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
)

// LockRunikIdentitySource serializes snapshots from one source across
// Management replicas. SQLite is single-writer and needs no advisory lock.
func (s *SqlStore) LockRunikIdentitySource(ctx context.Context, accountID, source string) error {
	if s.storeEngine != types.PostgresStoreEngine {
		return nil
	}
	return s.db.WithContext(ctx).
		Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", accountID+":"+source).Error
}

func (s *SqlStore) GetRunikIdentitySource(ctx context.Context, accountID, source string) (*types.RunikIdentitySource, error) {
	var state types.RunikIdentitySource
	err := s.db.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("account_id = ? AND source = ?", accountID, source).First(&state).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &state, err
}

func (s *SqlStore) SaveRunikIdentitySource(ctx context.Context, state *types.RunikIdentitySource) error {
	return s.db.WithContext(ctx).Save(state).Error
}

func (s *SqlStore) GetRunikIdentityUsers(ctx context.Context, accountID, source string) ([]*types.RunikIdentityUser, error) {
	var mappings []*types.RunikIdentityUser
	err := s.db.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("account_id = ? AND source = ?", accountID, source).Find(&mappings).Error
	return mappings, err
}

func (s *SqlStore) GetRunikIdentityUserByUserID(ctx context.Context, userID string) (*types.RunikIdentityUser, error) {
	var mapping types.RunikIdentityUser
	err := s.db.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("user_id = ?", userID).First(&mapping).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &mapping, err
}

func (s *SqlStore) SaveRunikIdentityUser(ctx context.Context, mapping *types.RunikIdentityUser) error {
	return s.db.WithContext(ctx).Save(mapping).Error
}

func (s *SqlStore) GetRunikIdentityGroups(ctx context.Context, accountID, source string) ([]*types.RunikIdentityGroup, error) {
	var mappings []*types.RunikIdentityGroup
	err := s.db.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("account_id = ? AND source = ?", accountID, source).Find(&mappings).Error
	return mappings, err
}

func (s *SqlStore) GetRunikIdentityGroupByGroupID(ctx context.Context, groupID string) (*types.RunikIdentityGroup, error) {
	var mapping types.RunikIdentityGroup
	err := s.db.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("group_id = ?", groupID).First(&mapping).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &mapping, err
}

func (s *SqlStore) SaveRunikIdentityGroup(ctx context.Context, mapping *types.RunikIdentityGroup) error {
	return s.db.WithContext(ctx).Save(mapping).Error
}
