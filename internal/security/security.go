package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidToken = errors.New("invalid token")

func HashPassword(pw string, cost int) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
	return string(b), err
}

func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// NewOTPCode menghasilkan 6 digit angka dengan CSPRNG.
func NewOTPCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// HashOTP: HMAC-SHA256 yang diikat ke target + purpose, sehingga kode tidak bisa dipakai lintas konteks.
func HashOTP(secret, target, purpose, code string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(target + "|" + purpose + "|" + code))
	return hex.EncodeToString(m.Sum(nil))
}

func EqualHash(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func HashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// NewOpaqueToken: 256-bit token acak (dikirim ke client) + hash-nya (disimpan di DB).
func NewOpaqueToken() (plain, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	plain = base64.RawURLEncoding.EncodeToString(b)
	return plain, HashToken(plain), nil
}

func NewUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type TokenManager struct {
	secret []byte
	issuer string
}

func NewTokenManager(secret, issuer string) *TokenManager {
	return &TokenManager{secret: []byte(secret), issuer: issuer}
}

type claims struct {
	jwt.RegisteredClaims
	Typ string `json:"typ"`
}

func (m *TokenManager) NewAccess(userID string, now time.Time, ttl time.Duration) (string, error) {
	c := claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: m.issuer, Subject: userID, ID: NewUUID(),
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Typ: "access",
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(m.secret)
}

func (m *TokenManager) ParseAccess(token string, now time.Time) (string, error) {
	c := &claims{}
	t, err := jwt.ParseWithClaims(token, c,
		func(*jwt.Token) (any, error) { return m.secret, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(m.issuer),
		jwt.WithExpirationRequired(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !t.Valid || c.Typ != "access" || c.Subject == "" {
		return "", ErrInvalidToken
	}
	return c.Subject, nil
}
