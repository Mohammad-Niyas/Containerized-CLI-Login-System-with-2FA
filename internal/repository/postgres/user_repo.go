package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (username, password_hash, mfa_enabled, totp_secret, failed_attempts)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at
	`
	err := r.pool.QueryRow(ctx, query,
		user.Username,
		user.PasswordHash,
		user.MFAEnabled,
		user.TOTPSecret,
		user.FailedAttempts,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // 23505 = unique_violation
			return domain.ErrUserAlreadyExists
		}
		return err
	}
	return nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	query := `
		SELECT id, username, password_hash, mfa_enabled, totp_secret, 
		       failed_attempts, locked_until, last_login_at, created_at, updated_at
		FROM users
		WHERE id = $1
	`
	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.MFAEnabled,
		&user.TOTPSecret,
		&user.FailedAttempts,
		&user.LockedUntil,
		&user.LastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	query := `
		SELECT id, username, password_hash, mfa_enabled, totp_secret, 
		       failed_attempts, locked_until, last_login_at, created_at, updated_at
		FROM users
		WHERE username = $1
	`
	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.MFAEnabled,
		&user.TOTPSecret,
		&user.FailedAttempts,
		&user.LockedUntil,
		&user.LastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) UpdateMFA(ctx context.Context, userID string, enabled bool, secret *string) error {
	query := `
		UPDATE users 
		SET mfa_enabled = $1, totp_secret = $2, updated_at = NOW()
		WHERE id = $3
	`
	cmdTag, err := r.pool.Exec(ctx, query, enabled, secret, userID)
	if err != nil {
		return err
	}
	if cmdTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) UpdateFailedAttempts(ctx context.Context, userID string, attempts int, lockedUntil *time.Time) error {
	query := `
		UPDATE users 
		SET failed_attempts = $1, locked_until = $2, updated_at = NOW()
		WHERE id = $3
	`
	cmdTag, err := r.pool.Exec(ctx, query, attempts, lockedUntil, userID)
	if err != nil {
		return err
	}
	if cmdTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) RecordSuccessfulLogin(ctx context.Context, userID string, loginTime time.Time) error {
	query := `
		UPDATE users 
		SET failed_attempts = 0, locked_until = NULL, last_login_at = $1, updated_at = NOW()
		WHERE id = $2
	`
	cmdTag, err := r.pool.Exec(ctx, query, loginTime, userID)
	if err != nil {
		return err
	}
	if cmdTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}