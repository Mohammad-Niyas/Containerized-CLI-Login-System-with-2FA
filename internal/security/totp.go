package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPServiceImpl implements domain.TOTPService
type TOTPServiceImpl struct {
	issuer string
}

func NewTOTPService(issuer string) *TOTPServiceImpl {
	if issuer == "" {
		issuer = "CLI-Auth-System"
	}
	return &TOTPServiceImpl{issuer: issuer}
}

func (s *TOTPServiceImpl) GenerateSecret(username string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: username,
		Period:      30,
		SecretSize:  20,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

func (s *TOTPServiceImpl) Validate(passcode, secret string) bool {
	return totp.Validate(passcode, secret)
}

// CryptoTokenGenerator implements domain.TokenGenerator
type CryptoTokenGenerator struct{}

func NewTokenGenerator() *CryptoTokenGenerator {
	return &CryptoTokenGenerator{}
}

func (g *CryptoTokenGenerator) GenerateToken() (string, string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	rawToken := hex.EncodeToString(bytes)
	tokenHash := g.HashToken(rawToken)
	return rawToken, tokenHash, nil
}

func (g *CryptoTokenGenerator) HashToken(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}