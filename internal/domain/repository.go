package domain

import (
	"context"
	"time"
)

// UserRepository defines the database contract for user persistence
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id string) (*User, error)
	GetByUsername(ctx context.Context, username string) (*User, error)
	UpdateMFA(ctx context.Context, userID string, enabled bool, secret *string) error
	UpdateFailedAttempts(ctx context.Context, userID string, attempts int, lockedUntil *time.Time) error
	RecordSuccessfulLogin(ctx context.Context, userID string, loginTime time.Time) error
}

// SessionRepository defines the database contract for session persistence
type SessionRepository interface {
    Create(ctx context.Context, session *Session) error
    GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
    DeleteByTokenHash(ctx context.Context, tokenHash string) error
    DeleteByUserID(ctx context.Context, userID string) error
}