package domain

import (
	"net/http"
	"time"
)

type User struct {
	ID               string
	FullName         string
	Email            string
	Phone            string
	PasswordHash     string
	FailedLoginCount int
	LockedUntil      *time.Time
	LastLoginAt      *time.Time
	AcceptedTermsAt  time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type OTPPurpose string
type OTPChannel string

const (
	PurposeLoginWhatsApp OTPPurpose = "login_whatsapp"
	PurposeResetPassword OTPPurpose = "reset_password"

	ChannelWhatsApp OTPChannel = "whatsapp"
	ChannelEmail    OTPChannel = "email"
)

type OTP struct {
	ID         string
	UserID     string
	Purpose    OTPPurpose
	Channel    OTPChannel
	Target     string
	CodeHash   string
	Attempts   int
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
	IP        string
	UserAgent string
	CreatedAt time.Time
}

type ResetToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// AppError adalah error yang aman ditampilkan ke client.
type AppError struct {
	Status  int               `json:"-"`
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
	Meta    map[string]any    `json:"meta,omitempty"`
}

func (e *AppError) Error() string { return e.Code + ": " + e.Message }

func NewError(status int, code, message string) *AppError {
	return &AppError{Status: status, Code: code, Message: message}
}

func (e *AppError) WithMessage(m string) *AppError { c := *e; c.Message = m; return &c }

func (e *AppError) WithDetails(d map[string]string) *AppError { c := *e; c.Details = d; return &c }

func (e *AppError) With(key string, v any) *AppError {
	c := *e
	c.Meta = map[string]any{}
	for k, val := range e.Meta {
		c.Meta[k] = val
	}
	c.Meta[key] = v
	return &c
}

var (
	ErrBadRequest         = NewError(http.StatusBadRequest, "bad_request", "Permintaan tidak valid.")
	ErrValidation         = NewError(http.StatusUnprocessableEntity, "validation_failed", "Data yang dikirim tidak valid.")
	ErrInvalidCredentials = NewError(http.StatusUnauthorized, "invalid_credentials", "Kombinasi email atau kata sandi tidak cocok.")
	ErrUnauthorized       = NewError(http.StatusUnauthorized, "unauthorized", "Token akses tidak ada, tidak valid, atau sudah kedaluwarsa.")
	ErrInvalidToken       = NewError(http.StatusUnauthorized, "invalid_token", "Refresh token tidak valid atau sudah kedaluwarsa.")
	ErrAccountLocked      = NewError(http.StatusLocked, "account_locked", "Akses masuk dibekukan sementara karena terlalu banyak percobaan gagal.")
	ErrConflict           = NewError(http.StatusConflict, "already_registered", "Email atau nomor WhatsApp sudah terdaftar.")
	ErrOTPInvalid         = NewError(http.StatusBadRequest, "otp_invalid", "Kode OTP salah.")
	ErrOTPExpired         = NewError(http.StatusBadRequest, "otp_expired", "Kode OTP tidak ditemukan atau sudah kedaluwarsa. Silakan minta kode baru.")
	ErrOTPCooldown        = NewError(http.StatusTooManyRequests, "otp_resend_cooldown", "Mohon tunggu sebelum meminta kode baru.")
	ErrResetTokenInvalid  = NewError(http.StatusBadRequest, "reset_token_invalid", "Sesi reset kata sandi tidak valid atau sudah kedaluwarsa.")
	ErrPasswordReused     = NewError(http.StatusUnprocessableEntity, "password_reused", "Kata sandi baru harus berbeda dari kata sandi yang pernah digunakan.")
	ErrTooManyRequests    = NewError(http.StatusTooManyRequests, "rate_limited", "Terlalu banyak permintaan. Coba lagi beberapa saat lagi.")
	ErrDeliveryFailed     = NewError(http.StatusBadGateway, "otp_delivery_failed", "Gagal mengirim kode verifikasi. Silakan coba lagi.")
	ErrInternal           = NewError(http.StatusInternalServerError, "internal_error", "Terjadi kesalahan pada server.")
)
