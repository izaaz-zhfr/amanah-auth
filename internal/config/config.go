package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Env         string // development | production
	Port        string
	StoreDriver string // postgres | memory
	DatabaseURL string

	JWTSecret string
	OTPSecret string
	JWTIssuer string

	AccessTTL         time.Duration
	SessionTTL        time.Duration // refresh token tanpa "ingat saya"
	RememberTTL       time.Duration // refresh token dengan "ingat saya"
	OTPTTL            time.Duration
	OTPResendCooldown time.Duration
	LockDuration      time.Duration
	ResetTokenTTL     time.Duration

	OTPMaxAttempts       int
	MaxLoginAttempts     int
	PasswordHistoryDepth int
	BcryptCost           int
	RateLimitPerMin      int
	LogOTP               bool // hanya untuk development: tulis kode OTP ke log
}

func Default() Config {
	return Config{
		Env: "development", Port: "8080", StoreDriver: "memory", JWTIssuer: "amanah-auth",
		JWTSecret: "test-secret-test-secret-test-secret-123", OTPSecret: "test-otp-secret-123456",
		AccessTTL: 15 * time.Minute, SessionTTL: 24 * time.Hour, RememberTTL: 30 * 24 * time.Hour,
		OTPTTL: 5 * time.Minute, OTPResendCooldown: 60 * time.Second,
		LockDuration: 15 * time.Minute, ResetTokenTTL: 10 * time.Minute,
		OTPMaxAttempts: 5, MaxLoginAttempts: 5, PasswordHistoryDepth: 3,
		BcryptCost: 12, RateLimitPerMin: 60,
	}
}

func Load() (Config, error) {
	c := Default()
	c.Env = env("APP_ENV", "development")
	c.Port = env("PORT", "8080")
	c.StoreDriver = env("STORE_DRIVER", "postgres")
	c.DatabaseURL = env("DATABASE_URL", "")
	c.JWTSecret = env("JWT_SECRET", "")
	c.OTPSecret = env("OTP_SECRET", "")
	c.JWTIssuer = env("JWT_ISSUER", c.JWTIssuer)
	c.AccessTTL = envDur("ACCESS_TOKEN_TTL", c.AccessTTL)
	c.SessionTTL = envDur("SESSION_TTL", c.SessionTTL)
	c.RememberTTL = envDur("REMEMBER_ME_TTL", c.RememberTTL)
	c.OTPTTL = envDur("OTP_TTL", c.OTPTTL)
	c.OTPResendCooldown = envDur("OTP_RESEND_COOLDOWN", c.OTPResendCooldown)
	c.LockDuration = envDur("LOCK_DURATION", c.LockDuration)
	c.ResetTokenTTL = envDur("RESET_TOKEN_TTL", c.ResetTokenTTL)
	c.OTPMaxAttempts = envInt("OTP_MAX_ATTEMPTS", c.OTPMaxAttempts)
	c.MaxLoginAttempts = envInt("MAX_LOGIN_ATTEMPTS", c.MaxLoginAttempts)
	c.PasswordHistoryDepth = envInt("PASSWORD_HISTORY_DEPTH", c.PasswordHistoryDepth)
	c.BcryptCost = envInt("BCRYPT_COST", c.BcryptCost)
	c.RateLimitPerMin = envInt("RATE_LIMIT_PER_MIN", c.RateLimitPerMin)
	c.LogOTP = env("LOG_OTP", "false") == "true"

	if len(c.JWTSecret) < 32 {
		return c, fmt.Errorf("JWT_SECRET wajib diisi (minimal 32 karakter)")
	}
	if len(c.OTPSecret) < 16 {
		return c, fmt.Errorf("OTP_SECRET wajib diisi (minimal 16 karakter)")
	}
	if c.StoreDriver == "postgres" && c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL wajib diisi untuk STORE_DRIVER=postgres")
	}
	if c.Env == "production" && c.LogOTP {
		return c, fmt.Errorf("LOG_OTP tidak boleh aktif di production")
	}
	if c.BcryptCost < 10 && c.Env == "production" {
		return c, fmt.Errorf("BCRYPT_COST minimal 10 di production")
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
