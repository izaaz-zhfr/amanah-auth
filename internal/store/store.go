package store

import (
	"context"
	"errors"
	"time"

	"amanah-auth/internal/domain"
)

var (
	ErrNotFound   = errors.New("store: not found")
	ErrEmailTaken = errors.New("store: email taken")
	ErrPhoneTaken = errors.New("store: phone taken")
)

// Store adalah satu-satunya pintu akses data. Semua waktu diberikan service (now) agar mudah dites.
type Store interface {
	// Users
	CreateUser(ctx context.Context, u *domain.User) error // juga menulis password_histories
	GetUserByID(ctx context.Context, id string) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	GetUserByPhone(ctx context.Context, phone string) (*domain.User, error)
	// RegisterFailedLogin menambah counter secara atomik. Bila mencapai max: counter di-reset dan akun dikunci
	// (lockedUntil != nil pada hasil).
	RegisterFailedLogin(ctx context.Context, userID string, max int, lock time.Duration, now time.Time) (failed int, lockedUntil *time.Time, err error)
	LockUser(ctx context.Context, userID string, until time.Time) error
	MarkLoginSuccess(ctx context.Context, userID string, now time.Time) error
	RecentPasswordHashes(ctx context.Context, userID string, limit int) ([]string, error)

	// OTP
	CreateOTP(ctx context.Context, o *domain.OTP) error // meng-consume OTP aktif sebelumnya (target+purpose)
	LatestOTP(ctx context.Context, target string, purpose domain.OTPPurpose) (*domain.OTP, error)
	IncrementOTPAttempts(ctx context.Context, id string) (int, error)
	ConsumeOTP(ctx context.Context, id string, now time.Time) (bool, error) // false bila sudah dipakai

	// Refresh token
	CreateRefreshToken(ctx context.Context, t *domain.RefreshToken) error
	GetRefreshToken(ctx context.Context, hash string) (*domain.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id string, now time.Time) (bool, error)
	RevokeUserRefreshTokens(ctx context.Context, userID string, now time.Time) error

	// Reset password
	CreateResetToken(ctx context.Context, t *domain.ResetToken) error
	GetResetToken(ctx context.Context, hash string) (*domain.ResetToken, error)
	// ResetPassword atomik: tandai token terpakai, ganti password, tulis riwayat, buka kunci, cabut semua refresh token.
	ResetPassword(ctx context.Context, userID, resetTokenID, newHash string, now time.Time) error

	DeleteExpired(ctx context.Context, now time.Time) error
}
