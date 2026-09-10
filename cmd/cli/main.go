package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/cli"
	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/repository/postgres"
	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/security"
	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/service"
)

func main() {
	// Graceful termination handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Read Environment Configurations with Sane Defaults
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "auth_user")
	dbPass := getEnv("DB_PASSWORD", "auth_password")
	dbName := getEnv("DB_NAME", "auth_db")

	sessionTimeoutMins := getEnvAsInt("SESSION_TIMEOUT_MINUTES", 15)
	maxFailedAttempts := getEnvAsInt("MAX_FAILED_ATTEMPTS", 5)
	lockoutDurationMins := getEnvAsInt("LOCKOUT_DURATION_MINUTES", 15)

	connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, dbPass, dbHost, dbPort, dbName)

	// Connect to PostgreSQL
	pool, err := postgres.NewConnectionPool(ctx, connString)
	if err != nil {
		fmt.Printf("Database connection error: %v\n", err)
		fmt.Println("Make sure PostgreSQL is running via: docker compose up -d db")
		os.Exit(1)
	}
	defer pool.Close()

	// Initialize Repositories
	userRepo := postgres.NewUserRepository(pool)
	sessionRepo := postgres.NewSessionRepository(pool)

	// Initialize Security Adapters
	hasher := security.NewBcryptHasher(10)
	totpSvc := security.NewTOTPService("CLI-Auth-2FA")
	tokenGen := security.NewTokenGenerator()

	// Initialize Services
	authConfig := service.AuthConfig{
		MaxFailedAttempts: maxFailedAttempts,
		LockoutDuration:   time.Duration(lockoutDurationMins) * time.Minute,
		SessionDuration:   time.Duration(sessionTimeoutMins) * time.Minute,
	}
	authService := service.NewAuthService(userRepo, sessionRepo, hasher, totpSvc, tokenGen, authConfig)
	mfaService := service.NewMFAService(userRepo, totpSvc)

	// Initialize CLI Inbound Adapter & Start REPL Loop
	handler := cli.NewCLIHandler(authService, mfaService)
	repl := cli.NewREPL(handler)

	if err := repl.Run(ctx); err != nil {
		fmt.Printf("Error running CLI: %v\n", err)
		os.Exit(1)
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvAsInt(key string, defaultVal int) int {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return defaultVal
	}
	return val
}