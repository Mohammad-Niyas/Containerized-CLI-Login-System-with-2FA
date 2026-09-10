package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/domain"
	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/security"
	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/service"
)

// In-memory Mock Repositories for lightning-fast testing
type mockUserRepo struct {
	users map[string]*domain.User
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: make(map[string]*domain.User)}
}

func (m *mockUserRepo) Create(ctx context.Context, user *domain.User) error {
	for _, u := range m.users {
		if u.Username == user.Username {
			return domain.ErrUserAlreadyExists
		}
	}
	user.ID = "mock-uuid-" + user.Username
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func (m *mockUserRepo) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	for _, u := range m.users {
		if u.Username == username {
			return u, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (m *mockUserRepo) UpdateMFA(ctx context.Context, userID string, enabled bool, secret *string) error {
	u, ok := m.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.MFAEnabled = enabled
	u.TOTPSecret = secret
	return nil
}

func (m *mockUserRepo) UpdateFailedAttempts(ctx context.Context, userID string, attempts int, lockedUntil *time.Time) error {
	u, ok := m.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.FailedAttempts = attempts
	u.LockedUntil = lockedUntil
	return nil
}

func (m *mockUserRepo) RecordSuccessfulLogin(ctx context.Context, userID string, loginTime time.Time) error {
	u, ok := m.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.FailedAttempts = 0
	u.LockedUntil = nil
	u.LastLoginAt = &loginTime
	return nil
}

type mockSessionRepo struct {
	sessions map[string]*domain.Session
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{sessions: make(map[string]*domain.Session)}
}

func (m *mockSessionRepo) Create(ctx context.Context, session *domain.Session) error {
	m.sessions[session.TokenHash] = session
	return nil
}

func (m *mockSessionRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	s, ok := m.sessions[tokenHash]
	if !ok {
		return nil, domain.ErrSessionExpired
	}
	return s, nil
}

func (m *mockSessionRepo) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	delete(m.sessions, tokenHash)
	return nil
}

func (m *mockSessionRepo) DeleteByUserID(ctx context.Context, userID string) error {
	for k, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, k)
		}
	}
	return nil
}

// TEST CASES

func TestAuthService_Register(t *testing.T) {
	userRepo := newMockUserRepo()
	sessionRepo := newMockSessionRepo()
	hasher := security.NewBcryptHasher(4) // low cost for fast test execution
	totp := security.NewTOTPService("Test")
	tokenGen := security.NewTokenGenerator()

	authService := service.NewAuthService(userRepo, sessionRepo, hasher, totp, tokenGen, service.AuthConfig{})

	ctx := context.Background()

	// Valid Registration
	user, err := authService.Register(ctx, "testuser", "securePassword123")
	if err != nil {
		t.Fatalf("expected successful registration, got: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("expected username testuser, got: %s", user.Username)
	}

	// Duplicate Username
	_, err = authService.Register(ctx, "testuser", "securePassword123")
	if !errors.Is(err, domain.ErrUserAlreadyExists) {
		t.Errorf("expected ErrUserAlreadyExists, got: %v", err)
	}

	// Password too short (< 8 chars)
	_, err = authService.Register(ctx, "newuser", "short")
	if !errors.Is(err, service.ErrPasswordTooShort) {
		t.Errorf("expected ErrPasswordTooShort, got: %v", err)
	}
}

func TestAuthService_AccountLockout(t *testing.T) {
	userRepo := newMockUserRepo()
	sessionRepo := newMockSessionRepo()
	hasher := security.NewBcryptHasher(4)
	totp := security.NewTOTPService("Test")
	tokenGen := security.NewTokenGenerator()

	cfg := service.AuthConfig{
		MaxFailedAttempts: 3, // Lock out after 3 attempts for this test
		LockoutDuration:   10 * time.Minute,
	}
	authService := service.NewAuthService(userRepo, sessionRepo, hasher, totp, tokenGen, cfg)
	ctx := context.Background()

	// Register user
	_, _ = authService.Register(ctx, "victim", "correctPassword123")

	// Attempt 1: Wrong password
	_, err := authService.Login(ctx, "victim", "wrongPassword", "")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("attempt 1: expected ErrInvalidCredentials, got: %v", err)
	}

	// Attempt 2: Wrong password
	_, err = authService.Login(ctx, "victim", "wrongPassword", "")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("attempt 2: expected ErrInvalidCredentials, got: %v", err)
	}

	// Attempt 3: Wrong password -> Reaches threshold, triggers lockout!
	_, err = authService.Login(ctx, "victim", "wrongPassword", "")
	if !errors.Is(err, domain.ErrAccountLocked) {
		t.Errorf("attempt 3: expected ErrAccountLocked, got: %v", err)
	}

	// Attempt 4: Even with CORRECT password, it must remain locked!
	_, err = authService.Login(ctx, "victim", "correctPassword123", "")
	if !errors.Is(err, domain.ErrAccountLocked) {
		t.Errorf("attempt 4 (with correct password): expected ErrAccountLocked, got: %v", err)
	}
}

func TestAuthService_SessionValidation(t *testing.T) {
	userRepo := newMockUserRepo()
	sessionRepo := newMockSessionRepo()
	hasher := security.NewBcryptHasher(4)
	totp := security.NewTOTPService("Test")
	tokenGen := security.NewTokenGenerator()

	cfg := service.AuthConfig{
		SessionDuration: 100 * time.Millisecond, // expires almost immediately
	}
	authService := service.NewAuthService(userRepo, sessionRepo, hasher, totp, tokenGen, cfg)
	ctx := context.Background()

	// Register & Login
	_, _ = authService.Register(ctx, "sessionuser", "correctPassword123")
	res, err := authService.Login(ctx, "sessionuser", "correctPassword123", "")
	if err != nil {
		t.Fatalf("expected login success, got: %v", err)
	}

	// Immediate session validation: Should succeed
	user, _, err := authService.ValidateSession(ctx, res.RawToken)
	if err != nil || user.Username != "sessionuser" {
		t.Fatalf("expected valid session, got: %v", err)
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Post-timeout validation: Must return ErrSessionExpired
	_, _, err = authService.ValidateSession(ctx, res.RawToken)
	if !errors.Is(err, domain.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired, got: %v", err)
	}
}