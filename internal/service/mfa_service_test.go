package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/domain"
	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/security"
	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/service"
	"github.com/pquerna/otp/totp"
)

func TestMFAService_SetupAndEnable(t *testing.T) {
	userRepo := newMockUserRepo()
	totpSvc := security.NewTOTPService("CLI-Auth-Test")
	mfaService := service.NewMFAService(userRepo, totpSvc)
	ctx := context.Background()

	// Create a dummy user
	user := &domain.User{Username: "john_doe"}
	_ = userRepo.Create(ctx, user)

	// Setup 2FA
	secret, qrURL, err := mfaService.Setup2FA(ctx, user.ID, user.Username)
	if err != nil {
		t.Fatalf("Setup2FA failed: %v", err)
	}
	if secret == "" || qrURL == "" {
		t.Fatal("expected non-empty secret and qrURL")
	}

	// Attempt Enable with INVALID code (should fail)
	err = mfaService.Enable2FA(ctx, user.ID, "000000", secret)
	if !errors.Is(err, domain.ErrInvalidMFA) {
		t.Errorf("expected ErrInvalidMFA, got %v", err)
	}

	// Attempt Enable with VALID code (using pquerna/otp to generate valid code for now)
	validCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate valid TOTP code: %v", err)
	}

	err = mfaService.Enable2FA(ctx, user.ID, validCode, secret)
	if err != nil {
		t.Fatalf("expected successful 2FA enablement, got: %v", err)
	}

	// Verify user state in DB is now MFA enabled
	updatedUser, _ := userRepo.GetByID(ctx, user.ID)
	if !updatedUser.MFAEnabled || updatedUser.TOTPSecret == nil || *updatedUser.TOTPSecret != secret {
		t.Errorf("expected user MFA to be enabled with secret, got enabled=%v", updatedUser.MFAEnabled)
	}

	// Disable 2FA
	err = mfaService.Disable2FA(ctx, user.ID)
	if err != nil {
		t.Fatalf("expected successful 2FA disablement, got: %v", err)
	}

	disabledUser, _ := userRepo.GetByID(ctx, user.ID)
	if disabledUser.MFAEnabled {
		t.Error("expected user MFA to be disabled")
	}
}

func TestAuthService_LoginWithMFAChallenge(t *testing.T) {
	userRepo := newMockUserRepo()
	sessionRepo := newMockSessionRepo()
	hasher := security.NewBcryptHasher(4)
	totpSvc := security.NewTOTPService("CLI-Auth-Test")
	tokenGen := security.NewTokenGenerator()

	cfg := service.AuthConfig{
		MaxFailedAttempts: 5, // Allows 5 attempts before lock
		LockoutDuration:   15 * time.Minute,
		SessionDuration:   30 * time.Minute,
	}
	authService := service.NewAuthService(userRepo, sessionRepo, hasher, totpSvc, tokenGen, cfg)
	ctx := context.Background()

	// Register user
	user, err := authService.Register(ctx, "mfa_login_user", "password123")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Enable MFA with known test secret
	secret := "JBSWY3DPEHPK3PXP"
	_ = userRepo.UpdateMFA(ctx, user.ID, true, &secret)

	// Login without OTP -> Must return ErrMFAChallengeRequired
	_, err = authService.Login(ctx, "mfa_login_user", "password123", "")
	if !errors.Is(err, service.ErrMFAChallengeRequired) {
		t.Errorf("expected ErrMFAChallengeRequired, got: %v", err)
	}

	// Login with invalid OTP -> Must fail with ErrInvalidMFA
	_, err = authService.Login(ctx, "mfa_login_user", "password123", "111111")
	if !errors.Is(err, domain.ErrInvalidMFA) {
		t.Errorf("expected ErrInvalidMFA, got: %v", err)
	}

	// Login with valid OTP -> Must succeed!
	validCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate valid TOTP code: %v", err)
	}

	res, err := authService.Login(ctx, "mfa_login_user", "password123", validCode)
	if err != nil {
		t.Fatalf("expected successful login with valid 2FA, got: %v", err)
	}
	if res.RawToken == "" {
		t.Error("expected non-empty session token")
	}
}