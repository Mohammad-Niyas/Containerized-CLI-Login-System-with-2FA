package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/domain"
	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/service"
	"github.com/chzyer/readline"
)

type CLIHandler struct {
	authService *service.AuthService
	mfaService  *service.MFAService
	rl          *readline.Instance

	// In-memory state for active terminal session
	sessionToken string
	currentUser  *domain.User
	expiresAt    time.Time
}

func NewCLIHandler(authService *service.AuthService, mfaService *service.MFAService) *CLIHandler {
	return &CLIHandler{
		authService: authService,
		mfaService:  mfaService,
	}
}

func (h *CLIHandler) SetReadline(rl *readline.Instance) {
	h.rl = rl
}

func (h *CLIHandler) IsLoggedIn() bool {
	return h.sessionToken != ""
}

func (h *CLIHandler) HandleRegister(ctx context.Context) {
	username, err := h.promptInput("Enter username: ")
	if err != nil || username == "" {
		return
	}

	passwordBytes, err := h.rl.ReadPassword("Enter password (min 8 chars): ")
	if err != nil {
		return
	}
	password := string(passwordBytes)

	user, err := h.authService.Register(ctx, username, password)
	if err != nil {
		fmt.Printf("Registration failed: %v\n", err)
		return
	}

	fmt.Printf("User '%s' registered successfully! You can now log in.\n", user.Username)
}

func (h *CLIHandler) HandleLogin(ctx context.Context) {
	username, err := h.promptInput("Enter username: ")
	if err != nil || username == "" {
		return
	}

	passwordBytes, err := h.rl.ReadPassword("Enter password: ")
	if err != nil {
		return
	}
	password := string(passwordBytes)

	// Step 1: First login attempt (without OTP)
	res, err := h.authService.Login(ctx, username, password, "")
	if err != nil {
		if errors.Is(err, service.ErrMFAChallengeRequired) {
			// MFA is enabled for this account! Prompt for 6-digit TOTP
			otpCode, err := h.promptInput("Enter 2FA TOTP Code (6 digits from Google Authenticator): ")
			if err != nil {
				return
			}

			// Step 2: Complete login with OTP
			res, err = h.authService.Login(ctx, username, password, otpCode)
			if err != nil {
				h.printError("Login failed", err)
				return
			}
		} else {
			h.printError("Login failed", err)
			return
		}
	}

	// Login successful: Save session state
	h.sessionToken = res.RawToken
	h.currentUser = res.User
	h.expiresAt = res.ExpiresAt

	fmt.Println("\n Login successful!")
	h.DisplayUserDetails(h.currentUser, h.expiresAt)
}

func (h *CLIHandler) HandleWhoAmI(ctx context.Context) {
	user, session, err := h.authService.ValidateSession(ctx, h.sessionToken)
	if err != nil {
		fmt.Println("Session invalid or expired. Please log in again.")
		h.logoutLocal()
		return
	}

	h.currentUser = user
	h.expiresAt = session.ExpiresAt
	h.DisplayUserDetails(user, session.ExpiresAt)
}

func (h *CLIHandler) HandleEnable2FA(ctx context.Context) {
	if !h.verifySession(ctx) {
		return
	}

	// 1. Setup secret
	secret, qrURL, err := h.mfaService.Setup2FA(ctx, h.currentUser.ID, h.currentUser.Username)
	if err != nil {
		h.printError("Failed to initiate 2FA", err)
		return
	}

	fmt.Println("\n 2FA SETUP")
	fmt.Printf("Secret Key: %s\n", secret)
	fmt.Printf("TOTP URI:   %s\n", qrURL)
	fmt.Println("Enter this Secret Key manually into Google Authenticator or your 2FA app.")

	// 2. Validate with confirmation code
	code, err := h.promptInput("\nEnter 6-digit verification code from your app: ")
	if err != nil {
		return
	}

	err = h.mfaService.Enable2FA(ctx, h.currentUser.ID, code, secret)
	if err != nil {
		h.printError("Failed to verify 2FA code", err)
		return
	}

	h.currentUser.MFAEnabled = true
	fmt.Println("2FA has been successfully enabled for your account!")
}

func (h *CLIHandler) HandleDisable2FA(ctx context.Context) {
	if !h.verifySession(ctx) {
		return
	}

	err := h.mfaService.Disable2FA(ctx, h.currentUser.ID)
	if err != nil {
		h.printError("Failed to disable 2FA", err)
		return
	}

	h.currentUser.MFAEnabled = false
	fmt.Println("2FA has been disabled.")
}

func (h *CLIHandler) HandleLogout(ctx context.Context) {
	if h.sessionToken != "" {
		_ = h.authService.Logout(ctx, h.sessionToken)
	}
	h.logoutLocal()
	fmt.Println("Successfully logged out.")
}

func (h *CLIHandler) DisplayUserDetails(user *domain.User, expiresAt time.Time) {
	fmt.Println("USER DETAILS")
	fmt.Printf("Username:            %s\n", user.Username)
	fmt.Printf("Registration Date:   %s\n", user.CreatedAt.Format(time.RFC1123))

	mfaStatus := "Disabled"
	if user.MFAEnabled {
		mfaStatus = "Enabled (Google Authenticator)"
	}
	fmt.Printf("MFA Status:          %s\n", mfaStatus)

	fmt.Printf("Session Expiration:  %s\n", expiresAt.Local().Format(time.RFC1123))

	lastLogin := "Never (First Login)"
	if user.LastLoginAt != nil {
		lastLogin = user.LastLoginAt.Local().Format(time.RFC1123)
	}

	fmt.Printf("Last Login:          %s\n", lastLogin)
	fmt.Println()
}

func (h *CLIHandler) DisplayHelp() {
	fmt.Println("\nAvailable Commands:")
	if !h.IsLoggedIn() {
		fmt.Println("  register   - Create a new account")
		fmt.Println("  login      - Authenticate with username and password (+ 2FA)")
		fmt.Println("  help       - Show available commands")
		fmt.Println("  exit       - Exit the program")
	} else {
		fmt.Println("  whoami      - Display current user details and session status")
		fmt.Println("  enable-2fa  - Setup and enable TOTP two-factor authentication")
		fmt.Println("  disable-2fa - Turn off two-factor authentication")
		fmt.Println("  logout      - Terminate current session")
		fmt.Println("  help        - Show available commands")
		fmt.Println("  exit        - Exit the program")
	}
	fmt.Println()
}

func (h *CLIHandler) verifySession(ctx context.Context) bool {
	user, _, err := h.authService.ValidateSession(ctx, h.sessionToken)
	if err != nil {
		fmt.Println("Session expired or invalid. Please log in again.")
		h.logoutLocal()
		return false
	}
	h.currentUser = user
	return true
}

func (h *CLIHandler) logoutLocal() {
	h.sessionToken = ""
	h.currentUser = nil
	h.expiresAt = time.Time{}
}

func (h *CLIHandler) printError(prefix string, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidCredentials):
		fmt.Printf("%s: Invalid username or password.\n", prefix)
	case errors.Is(err, domain.ErrAccountLocked):
		fmt.Printf("%s: Account is temporarily locked due to multiple failed login attempts.\n", prefix)
	case errors.Is(err, domain.ErrInvalidMFA):
		fmt.Printf("%s: Invalid 2FA verification code.\n", prefix)
	default:
		fmt.Printf("%s: %v\n", prefix, err)
	}
}

func (h *CLIHandler) promptInput(prompt string) (string, error) {
	h.rl.SetPrompt(prompt)
	defer func() {
		if h.IsLoggedIn() && h.currentUser != nil {
			h.rl.SetPrompt(fmt.Sprintf("auth-cli (%s)> ", h.currentUser.Username))
		} else {
			h.rl.SetPrompt("auth-cli> ")
		}
	}()

	line, err := h.rl.Readline()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}