package service

import (
	"context"
	"fmt"

	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/domain"
)

type MFAService struct {
	userRepo    domain.UserRepository
	totpService domain.TOTPService
}

func NewMFAService(userRepo domain.UserRepository, totpService domain.TOTPService) *MFAService {
	return &MFAService{
		userRepo:    userRepo,
		totpService: totpService,
	}
}

// initiates the 2FA enablement by generating a secret
func (s *MFAService) Setup2FA(ctx context.Context, userID, username string) (secret string, qrURL string, err error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if user.MFAEnabled {
		return "", "", domain.ErrMFAAlreadyEnabled
	}

	secret, qrURL, err = s.totpService.GenerateSecret(username)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	return secret, qrURL, nil
}

// confirms the secret with a valid 6-digit code and activates 2FA
func (s *MFAService) Enable2FA(ctx context.Context, userID, otpCode, secret string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.MFAEnabled {
		return domain.ErrMFAAlreadyEnabled
	}

	// Verify the OTP against the secret
	if !s.totpService.Validate(otpCode, secret) {
		return domain.ErrInvalidMFA
	}

	// enabled status and secret
	return s.userRepo.UpdateMFA(ctx, userID, true, &secret)
}

// disables 2FA for the user
func (s *MFAService) Disable2FA(ctx context.Context, userID string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if !user.MFAEnabled {
		return domain.ErrMFANotEnabled
	}

	return s.userRepo.UpdateMFA(ctx, userID, false, nil)
}