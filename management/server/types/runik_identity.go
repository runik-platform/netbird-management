package types

import "time"

// RunikIdentitySource records the last complete authoritative snapshot applied
// for one external identity source in an account.
type RunikIdentitySource struct {
	ID           string `gorm:"primaryKey;size:64"`
	AccountID    string `gorm:"index;size:255;not null"`
	Source       string `gorm:"size:255;not null"`
	InstanceID   string `gorm:"size:255;not null"`
	Revision     string `gorm:"size:255;not null"`
	SnapshotHash string `gorm:"size:64;not null"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// RunikIdentityUser binds the stable external issuer+subject identity to the
// NetBird user ID that OIDC presents on first and subsequent logins.
type RunikIdentityUser struct {
	ID        string `gorm:"primaryKey;size:64"`
	AccountID string `gorm:"index;size:255;not null"`
	Source    string `gorm:"size:255;not null"`
	Issuer    string `gorm:"not null"`
	Subject   string `gorm:"not null"`
	UserID    string `gorm:"size:255;not null;uniqueIndex"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RunikIdentityGroup binds an arbitrary external group ID to a stable NetBird
// group ID. Names may change without changing this association.
type RunikIdentityGroup struct {
	ID         string `gorm:"primaryKey;size:64"`
	AccountID  string `gorm:"index;size:255;not null"`
	Source     string `gorm:"size:255;not null"`
	ExternalID string `gorm:"not null"`
	GroupID    string `gorm:"size:255;not null;uniqueIndex"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
