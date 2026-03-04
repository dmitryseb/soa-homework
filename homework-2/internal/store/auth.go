package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"

	"soa/homework-2/internal/api"
)

var ErrAlreadyExists = errors.New("already exists")

type AuthStore struct {
	db *sql.DB
}

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	Role         api.UserRole
}

type RefreshToken struct {
	TokenHash string
	UserID    int64
	ExpiresAt time.Time
}

func NewAuthStore(db *sql.DB) *AuthStore {
	return &AuthStore{db: db}
}

func (s *AuthStore) CreateUser(ctx context.Context, email, passwordHash string, role api.UserRole) (User, error) {
	var user User
	err := s.db.QueryRowContext(
		ctx,
		`INSERT INTO users (email, password_hash, role)
		 VALUES ($1, $2, $3)
		 RETURNING id, email, password_hash, role`,
		email,
		passwordHash,
		role,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return User{}, ErrAlreadyExists
		}
		return User{}, err
	}
	return user, nil
}

func (s *AuthStore) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var user User
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, email, password_hash, role
		 FROM users
		 WHERE email = $1`,
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	return user, nil
}

func (s *AuthStore) GetUserByID(ctx context.Context, id int64) (User, error) {
	var user User
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, email, password_hash, role
		 FROM users
		 WHERE id = $1`,
		id,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	return user, nil
}

func (s *AuthStore) SaveRefreshToken(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO refresh_tokens (token_hash, user_id, expires_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (token_hash) DO UPDATE
		 SET user_id = EXCLUDED.user_id,
		     expires_at = EXCLUDED.expires_at`,
		tokenHash,
		userID,
		expiresAt.UTC(),
	)
	return err
}

func (s *AuthStore) GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, error) {
	var token RefreshToken
	err := s.db.QueryRowContext(
		ctx,
		`SELECT token_hash, user_id, expires_at
		 FROM refresh_tokens
		 WHERE token_hash = $1`,
		tokenHash,
	).Scan(&token.TokenHash, &token.UserID, &token.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RefreshToken{}, ErrNotFound
		}
		return RefreshToken{}, err
	}
	if !token.ExpiresAt.After(time.Now().UTC()) {
		return RefreshToken{}, ErrNotFound
	}
	return token, nil
}
