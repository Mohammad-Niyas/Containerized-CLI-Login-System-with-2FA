package domain

// Password Hasher (bcrypt)
type PasswordHasher interface {
    Hash(password string) (string, error)
    Compare(hashedPassword, password string) error
}

// TOTP Service (Google Authenticator)
type TOTPService interface {
    GenerateSecret(username string) (secret string, qrCodeURL string, err error)
    Validate(passcode, secret string) bool
}

// Token Generator (CSPRNG session tokens)
type TokenGenerator interface {
    GenerateToken() (rawToken string, tokenHash string, err error)
    HashToken(rawToken string) string
}