package domain

import (
    "errors"
    "time"
)

// Standard Sentinel Domain Errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists   = errors.New("username already taken")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is temporarily locked due to multiple failed login attempts")
	ErrInvalidMFA         = errors.New("invalid 2FA code")
	ErrMFANotEnabled      = errors.New("2FA is not enabled for this user")
	ErrMFAAlreadyEnabled  = errors.New("2FA is already enabled for this user")
	ErrSessionExpired     = errors.New("session has expired, please log in again")
	ErrUnauthorized       = errors.New("unauthorized action")
)

// User entity representing an account in our system
type User struct {
    ID             string
    Username       string
    PasswordHash   string
    MFAEnabled     bool
    TOTPSecret     *string
    FailedAttempts int
    LockedUntil    *time.Time
    LastLoginAt    *time.Time
    CreatedAt      time.Time
    UpdatedAt      time.Time
}

// Session entity representing an active session token
type Session struct {
    ID        string
    UserID    string
    TokenHash string
    ExpiresAt time.Time
    CreatedAt time.Time
}