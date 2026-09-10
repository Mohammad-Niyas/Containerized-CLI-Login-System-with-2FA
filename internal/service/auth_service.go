package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/domain"
)

var (
	ErrPasswordTooShort     = errors.New("password must be at least 8 characters")
	ErrUsernameEmpty        = errors.New("username cannot be empty")
	ErrMFAChallengeRequired = errors.New("2FA code required")
)

type AuthConfig struct {
	MaxFailedAttempts int
	LockoutDuration   time.Duration
	SessionDuration   time.Duration
}

type AuthService struct {
	userRepo       domain.UserRepository
	sessionRepo    domain.SessionRepository
	hasher         domain.PasswordHasher
	totpService    domain.TOTPService
	tokenGenerator domain.TokenGenerator
	config         AuthConfig
}

func NewAuthService(
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
	hasher domain.PasswordHasher,
	totpService domain.TOTPService,
	tokenGenerator domain.TokenGenerator,
	config AuthConfig,
) *AuthService {

	return &AuthService{
		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		hasher:         hasher,
		totpService:    totpService,
		tokenGenerator: tokenGenerator,
		config:         config,
	}
}

type AuthResult struct {
	User      *domain.User
	RawToken  string
	ExpiresAt time.Time
}

func (s *AuthService) Register(ctx context.Context, username, password string) (*domain.User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, ErrUsernameEmpty
	}
	if len(password) < 8 {
		return nil, ErrPasswordTooShort
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	user := &domain.User{
		Username:     username,
		PasswordHash: hash,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *AuthService) Login(ctx context.Context, username, password, otpCode string) (*AuthResult, error) {
	username = strings.TrimSpace(username)
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	now := time.Now()

	// Check lockout status
	if user.LockedUntil != nil && user.LockedUntil.After(now) {
		return nil, domain.ErrAccountLocked
	}

	// Verify password
	if err := s.hasher.Compare(user.PasswordHash, password); err != nil {
		return nil, s.handleFailedAttempt(ctx, user, now, domain.ErrInvalidCredentials)
	}

	// Verify MFA if enabled
	if user.MFAEnabled {
		if otpCode == "" {
			return nil, ErrMFAChallengeRequired
		}
		if user.TOTPSecret == nil || !s.totpService.Validate(otpCode, *user.TOTPSecret) {
			return nil, s.handleFailedAttempt(ctx, user, now, domain.ErrInvalidMFA)
		}
	}

	// Reset failed attempts & record login
	if err := s.userRepo.RecordSuccessfulLogin(ctx, user.ID, now); err != nil {
		return nil, err
	}
	user.LastLoginAt = &now
	user.FailedAttempts = 0
	user.LockedUntil = nil

	// Create Session
	rawToken, tokenHash, err := s.tokenGenerator.GenerateToken()
	if err != nil {
		return nil, err
	}

	expiresAt := now.Add(s.config.SessionDuration)
	session := &domain.Session{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	return &AuthResult{
		User:      user,
		RawToken:  rawToken,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *AuthService) ValidateSession(ctx context.Context, rawToken string) (*domain.User, *domain.Session, error) {
	tokenHash := s.tokenGenerator.HashToken(rawToken)
	session, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil,nil, err
	}

	if time.Now().After(session.ExpiresAt) {
		_ = s.sessionRepo.DeleteByTokenHash(ctx, tokenHash)
		return nil, nil, domain.ErrSessionExpired
	}

	user, err := s.userRepo.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, nil, err
	}

	return user, session, nil
}

func (s *AuthService) Logout(ctx context.Context, rawToken string) error {
	tokenHash := s.tokenGenerator.HashToken(rawToken)
	return s.sessionRepo.DeleteByTokenHash(ctx, tokenHash)
}

func (s *AuthService) handleFailedAttempt(ctx context.Context, user *domain.User, now time.Time, fallbackErr error) error {
	attempts := user.FailedAttempts + 1
	var lockedUntil *time.Time

	if attempts >= s.config.MaxFailedAttempts {
		lockTime := now.Add(s.config.LockoutDuration)
		lockedUntil = &lockTime
	}

	_ = s.userRepo.UpdateFailedAttempts(ctx, user.ID, attempts, lockedUntil)

	if lockedUntil != nil {
		return domain.ErrAccountLocked
	}
	return fallbackErr
}