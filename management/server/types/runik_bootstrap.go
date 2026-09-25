package types

import "time"

const (
	RunikBootstrapPhaseBootstrapping = "bootstrapping"
	RunikBootstrapPhaseSealed        = "sealed"
)

// RunikBootstrapState records the one-shot bootstrap lifecycle. The bootstrap
// credential and the plaintext PAT are deliberately never persisted here.
type RunikBootstrapState struct {
	InstanceID    string `gorm:"primaryKey;size:255"`
	AccountID     string `gorm:"uniqueIndex;size:255;not null"`
	AccountName   string `gorm:"size:255;not null"`
	OwnerUserID   string `gorm:"uniqueIndex;size:255;not null"`
	ActiveTokenID string `gorm:"size:255;not null"`
	Phase         string `gorm:"size:32;not null"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
	SealedAt      *time.Time
}
