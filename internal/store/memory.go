package store

import (
	"context"
	"strings"
	"sync"
	"time"

	"amanah-auth/internal/domain"
)

// Memory: implementasi in-memory (untuk unit test & demo lokal tanpa database).
type Memory struct {
	mu      sync.Mutex
	users   map[string]*domain.User
	otps    []*domain.OTP
	refresh map[string]*domain.RefreshToken
	resets  map[string]*domain.ResetToken
	history map[string][]string // userID -> hash (terbaru di akhir)
}

func NewMemory() *Memory {
	return &Memory{
		users: map[string]*domain.User{}, refresh: map[string]*domain.RefreshToken{},
		resets: map[string]*domain.ResetToken{}, history: map[string][]string{},
	}
}

func cp[T any](v *T) *T { c := *v; return &c }

func (m *Memory) CreateUser(_ context.Context, u *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.users {
		if e.Email == u.Email {
			return ErrEmailTaken
		}
		if e.Phone == u.Phone {
			return ErrPhoneTaken
		}
	}
	m.users[u.ID] = cp(u)
	m.history[u.ID] = append(m.history[u.ID], u.PasswordHash)
	return nil
}

func (m *Memory) find(f func(*domain.User) bool) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if f(u) {
			return cp(u), nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) GetUserByID(_ context.Context, id string) (*domain.User, error) {
	return m.find(func(u *domain.User) bool { return u.ID == id })
}
func (m *Memory) GetUserByEmail(_ context.Context, e string) (*domain.User, error) {
	return m.find(func(u *domain.User) bool { return u.Email == strings.ToLower(e) })
}
func (m *Memory) GetUserByPhone(_ context.Context, p string) (*domain.User, error) {
	return m.find(func(u *domain.User) bool { return u.Phone == p })
}

func (m *Memory) RegisterFailedLogin(_ context.Context, id string, max int, lock time.Duration, now time.Time) (int, *time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return 0, nil, ErrNotFound
	}
	u.FailedLoginCount++
	u.UpdatedAt = now
	if u.FailedLoginCount >= max {
		until := now.Add(lock)
		u.FailedLoginCount, u.LockedUntil = 0, &until
		return 0, &until, nil
	}
	u.LockedUntil = nil
	return u.FailedLoginCount, nil, nil
}

func (m *Memory) LockUser(_ context.Context, id string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return ErrNotFound
	}
	u.LockedUntil, u.FailedLoginCount = &until, 0
	return nil
}

func (m *Memory) MarkLoginSuccess(_ context.Context, id string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return ErrNotFound
	}
	u.FailedLoginCount, u.LockedUntil, u.LastLoginAt = 0, nil, &now
	return nil
}

func (m *Memory) RecentPasswordHashes(_ context.Context, id string, limit int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.history[id]
	out := []string{}
	for i := len(h) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, h[i])
	}
	return out, nil
}

func (m *Memory) CreateOTP(_ context.Context, o *domain.OTP) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.otps {
		if e.Target == o.Target && e.Purpose == o.Purpose && e.ConsumedAt == nil {
			t := o.CreatedAt
			e.ConsumedAt = &t
		}
	}
	m.otps = append(m.otps, cp(o))
	return nil
}

func (m *Memory) LatestOTP(_ context.Context, target string, p domain.OTPPurpose) (*domain.OTP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.otps) - 1; i >= 0; i-- {
		if o := m.otps[i]; o.Target == target && o.Purpose == p {
			return cp(o), nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) IncrementOTPAttempts(_ context.Context, id string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.otps {
		if o.ID == id {
			o.Attempts++
			return o.Attempts, nil
		}
	}
	return 0, ErrNotFound
}

func (m *Memory) ConsumeOTP(_ context.Context, id string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.otps {
		if o.ID == id {
			if o.ConsumedAt != nil {
				return false, nil
			}
			o.ConsumedAt = &now
			return true, nil
		}
	}
	return false, ErrNotFound
}

func (m *Memory) CreateRefreshToken(_ context.Context, t *domain.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[t.ID] = cp(t)
	return nil
}

func (m *Memory) GetRefreshToken(_ context.Context, hash string) (*domain.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.refresh {
		if t.TokenHash == hash {
			return cp(t), nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) RevokeRefreshToken(_ context.Context, id string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.refresh[id]
	if !ok {
		return false, ErrNotFound
	}
	if t.RevokedAt != nil {
		return false, nil
	}
	t.RevokedAt = &now
	return true, nil
}

func (m *Memory) RevokeUserRefreshTokens(_ context.Context, userID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeAll(userID, now)
	return nil
}

func (m *Memory) revokeAll(userID string, now time.Time) {
	for _, t := range m.refresh {
		if t.UserID == userID && t.RevokedAt == nil {
			n := now
			t.RevokedAt = &n
		}
	}
}

func (m *Memory) CreateResetToken(_ context.Context, t *domain.ResetToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resets[t.ID] = cp(t)
	return nil
}

func (m *Memory) GetResetToken(_ context.Context, hash string) (*domain.ResetToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.resets {
		if t.TokenHash == hash {
			return cp(t), nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) ResetPassword(_ context.Context, userID, tokenID, newHash string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.resets[tokenID]
	if !ok || t.UsedAt != nil || !now.Before(t.ExpiresAt) {
		return ErrNotFound
	}
	u, ok := m.users[userID]
	if !ok {
		return ErrNotFound
	}
	t.UsedAt = &now
	u.PasswordHash, u.FailedLoginCount, u.LockedUntil, u.UpdatedAt = newHash, 0, nil, now
	m.history[userID] = append(m.history[userID], newHash)
	m.revokeAll(userID, now)
	return nil
}

func (m *Memory) DeleteExpired(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := now.Add(-24 * time.Hour)
	keep := m.otps[:0]
	for _, o := range m.otps {
		if o.ExpiresAt.After(cutoff) {
			keep = append(keep, o)
		}
	}
	m.otps = keep
	for id, t := range m.refresh {
		if t.ExpiresAt.Before(cutoff) {
			delete(m.refresh, id)
		}
	}
	for id, t := range m.resets {
		if t.ExpiresAt.Before(cutoff) {
			delete(m.resets, id)
		}
	}
	return nil
}
