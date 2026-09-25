package store

import (
	"context"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
)

// LockRunikBootstrap serializes bootstrap for an instance across Management
// replicas. SQLite already serializes writes and is only supported with one
// writer; PostgreSQL needs an explicit transaction-scoped advisory lock.
func (s *SqlStore) LockRunikBootstrap(ctx context.Context, instanceID string) error {
	if s.storeEngine != types.PostgresStoreEngine {
		return nil
	}
	return s.db.WithContext(ctx).
		Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", instanceID).Error
}

func (s *SqlStore) GetRunikBootstrapState(ctx context.Context, instanceID string) (*types.RunikBootstrapState, error) {
	var state types.RunikBootstrapState
	err := s.db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("instance_id = ?", instanceID).
		First(&state).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &state, nil
}

func (s *SqlStore) SaveRunikBootstrapState(ctx context.Context, state *types.RunikBootstrapState) error {
	return s.db.WithContext(ctx).Save(state).Error
}
