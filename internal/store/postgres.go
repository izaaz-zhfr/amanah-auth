package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"amanah-auth/internal/domain"

	"github.com/lib/pq"
)

type Postgres struct{ db *sql.DB }

func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pctx); err != nil {
		return nil, err
	}
	return &Postgres{db: db}, nil
}

func (p *Postgres) Close() error { return p.db.Close() }

const userCols = `id, full_name, email, phone, password_hash, failed_login_count, locked_until,
	last_login_at, terms_accepted_at, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func ptr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

func scanUser(r scanner) (*domain.User, error) {
	var u domain.User
	var locked, last sql.NullTime
	err := r.Scan(&u.ID, &u.FullName, &u.Email, &u.Phone, &u.PasswordHash, &u.FailedLoginCount,
		&locked, &last, &u.AcceptedTermsAt, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.LockedUntil, u.LastLoginAt = ptr(locked), ptr(last)
	return &u, nil
}

func (p *Postgres) CreateUser(ctx context.Context, u *domain.User) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO users (id, full_name, email, phone, password_hash,
		terms_accepted_at, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)`,
		u.ID, u.FullName, u.Email, u.Phone, u.PasswordHash, u.AcceptedTermsAt, u.CreatedAt)
	if err != nil {
		var pe *pq.Error
		if errors.As(err, &pe) && pe.Code == "23505" {
			switch pe.Constraint {
			case "uq_users_email":
				return ErrEmailTaken
			case "uq_users_phone":
				return ErrPhoneTaken
			}
		}
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO password_histories (user_id, password_hash, created_at)
		VALUES ($1,$2,$3)`, u.ID, u.PasswordHash, u.CreatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *Postgres) getUser(ctx context.Context, where string, arg any) (*domain.User, error) {
	return scanUser(p.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE `+where, arg))
}
func (p *Postgres) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	return p.getUser(ctx, "id = $1", id)
}
func (p *Postgres) GetUserByEmail(ctx context.Context, e string) (*domain.User, error) {
	return p.getUser(ctx, "email = lower($1)", e)
}
func (p *Postgres) GetUserByPhone(ctx context.Context, ph string) (*domain.User, error) {
	return p.getUser(ctx, "phone = $1", ph)
}

func (p *Postgres) RegisterFailedLogin(ctx context.Context, id string, max int, lock time.Duration, now time.Time) (int, *time.Time, error) {
	var failed int
	var locked sql.NullTime
	err := p.db.QueryRowContext(ctx, `UPDATE users SET
		failed_login_count = CASE WHEN failed_login_count + 1 >= $2 THEN 0 ELSE failed_login_count + 1 END,
		locked_until       = CASE WHEN failed_login_count + 1 >= $2 THEN $3::timestamptz ELSE NULL END,
		updated_at = $4
		WHERE id = $1 RETURNING failed_login_count, locked_until`,
		id, max, now.Add(lock), now).Scan(&failed, &locked)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, ErrNotFound
	}
	return failed, ptr(locked), err
}

func (p *Postgres) LockUser(ctx context.Context, id string, until time.Time) error {
	_, err := p.db.ExecContext(ctx, `UPDATE users SET locked_until=$2, failed_login_count=0, updated_at=now() WHERE id=$1`, id, until)
	return err
}

func (p *Postgres) MarkLoginSuccess(ctx context.Context, id string, now time.Time) error {
	_, err := p.db.ExecContext(ctx, `UPDATE users SET failed_login_count=0, locked_until=NULL, last_login_at=$2, updated_at=$2 WHERE id=$1`, id, now)
	return err
}

func (p *Postgres) RecentPasswordHashes(ctx context.Context, id string, limit int) ([]string, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT password_hash FROM password_histories
		WHERE user_id=$1 ORDER BY created_at DESC, id DESC LIMIT $2`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (p *Postgres) CreateOTP(ctx context.Context, o *domain.OTP) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE otp_codes SET consumed_at=$3
		WHERE target=$1 AND purpose=$2 AND consumed_at IS NULL`, o.Target, o.Purpose, o.CreatedAt); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO otp_codes (id, user_id, purpose, channel, target, code_hash, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, o.ID, o.UserID, o.Purpose, o.Channel, o.Target, o.CodeHash, o.ExpiresAt, o.CreatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *Postgres) LatestOTP(ctx context.Context, target string, purpose domain.OTPPurpose) (*domain.OTP, error) {
	var o domain.OTP
	var consumed sql.NullTime
	err := p.db.QueryRowContext(ctx, `SELECT id, user_id, purpose, channel, target, code_hash, attempts, expires_at, consumed_at, created_at
		FROM otp_codes WHERE target=$1 AND purpose=$2 ORDER BY created_at DESC LIMIT 1`, target, purpose).
		Scan(&o.ID, &o.UserID, &o.Purpose, &o.Channel, &o.Target, &o.CodeHash, &o.Attempts, &o.ExpiresAt, &consumed, &o.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	o.ConsumedAt = ptr(consumed)
	return &o, err
}

func (p *Postgres) IncrementOTPAttempts(ctx context.Context, id string) (int, error) {
	var n int
	err := p.db.QueryRowContext(ctx, `UPDATE otp_codes SET attempts=attempts+1 WHERE id=$1 RETURNING attempts`, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return n, err
}

func (p *Postgres) ConsumeOTP(ctx context.Context, id string, now time.Time) (bool, error) {
	res, err := p.db.ExecContext(ctx, `UPDATE otp_codes SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL`, id, now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (p *Postgres) CreateRefreshToken(ctx context.Context, t *domain.RefreshToken) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, ip_address, user_agent, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, t.ID, t.UserID, t.TokenHash, t.ExpiresAt, t.IP, t.UserAgent, t.CreatedAt)
	return err
}

func (p *Postgres) GetRefreshToken(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	var t domain.RefreshToken
	var revoked sql.NullTime
	var ip, ua sql.NullString
	err := p.db.QueryRowContext(ctx, `SELECT id, user_id, token_hash, expires_at, revoked_at, ip_address, user_agent, created_at
		FROM refresh_tokens WHERE token_hash=$1`, hash).
		Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &revoked, &ip, &ua, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	t.RevokedAt, t.IP, t.UserAgent = ptr(revoked), ip.String, ua.String
	return &t, err
}

func (p *Postgres) RevokeRefreshToken(ctx context.Context, id string, now time.Time) (bool, error) {
	res, err := p.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at=$2 WHERE id=$1 AND revoked_at IS NULL`, id, now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (p *Postgres) RevokeUserRefreshTokens(ctx context.Context, userID string, now time.Time) error {
	_, err := p.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at=$2 WHERE user_id=$1 AND revoked_at IS NULL`, userID, now)
	return err
}

func (p *Postgres) CreateResetToken(ctx context.Context, t *domain.ResetToken) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5)`, t.ID, t.UserID, t.TokenHash, t.ExpiresAt, t.CreatedAt)
	return err
}

func (p *Postgres) GetResetToken(ctx context.Context, hash string) (*domain.ResetToken, error) {
	var t domain.ResetToken
	var used sql.NullTime
	err := p.db.QueryRowContext(ctx, `SELECT id, user_id, token_hash, expires_at, used_at, created_at
		FROM password_reset_tokens WHERE token_hash=$1`, hash).
		Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &used, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	t.UsedAt = ptr(used)
	return &t, err
}

func (p *Postgres) ResetPassword(ctx context.Context, userID, tokenID, newHash string, now time.Time) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE password_reset_tokens SET used_at=$2
		WHERE id=$1 AND used_at IS NULL AND expires_at > $2`, tokenID, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET password_hash=$2, failed_login_count=0, locked_until=NULL, updated_at=$3
		WHERE id=$1`, userID, newHash, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO password_histories (user_id, password_hash, created_at) VALUES ($1,$2,$3)`,
		userID, newHash, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at=$2 WHERE user_id=$1 AND revoked_at IS NULL`, userID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *Postgres) DeleteExpired(ctx context.Context, now time.Time) error {
	cutoff := now.Add(-24 * time.Hour)
	for _, q := range []string{
		`DELETE FROM otp_codes WHERE expires_at < $1`,
		`DELETE FROM refresh_tokens WHERE expires_at < $1`,
		`DELETE FROM password_reset_tokens WHERE expires_at < $1`,
	} {
		if _, err := p.db.ExecContext(ctx, q, cutoff); err != nil {
			return err
		}
	}
	return nil
}
