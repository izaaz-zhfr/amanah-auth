package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"amanah-auth/internal/config"
	"amanah-auth/internal/domain"
	"amanah-auth/internal/notify"
	"amanah-auth/internal/security"
	"amanah-auth/internal/store"
)

type ClientMeta struct{ IP, UserAgent string }

type Service struct {
	cfg    config.Config
	store  store.Store
	send   notify.Sender
	tokens *security.TokenManager
	log    *slog.Logger
	Now    func() time.Time
	dummy  string // hash palsu agar waktu respons login tidak membocorkan keberadaan email
}

func New(cfg config.Config, st store.Store, sender notify.Sender, log *slog.Logger) *Service {
	d, _ := security.HashPassword("dummy-password-Aa1!", cfg.BcryptCost)
	return &Service{
		cfg: cfg, store: st, send: sender, log: log, dummy: d,
		tokens: security.NewTokenManager(cfg.JWTSecret, cfg.JWTIssuer),
		Now:    func() time.Time { return time.Now().UTC() },
	}
}

// ---------- DTO ----------

type UserView struct {
	ID          string     `json:"id"`
	FullName    string     `json:"full_name"`
	Email       string     `json:"email"`
	Phone       string     `json:"phone"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

type AuthResult struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
	User         UserView `json:"user"`
}

type OTPSent struct {
	Channel           string `json:"channel"`
	Destination       string `json:"destination"`
	ExpiresIn         int    `json:"expires_in"`
	ResendAvailableIn int    `json:"resend_available_in"`
}

type RegisterInput struct {
	FullName        string `json:"full_name"`
	Email           string `json:"email"`
	Phone           string `json:"phone"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	AcceptTerms     bool   `json:"accept_terms"`
}

type LoginInput struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
}

type PhoneInput struct {
	Phone string `json:"phone"`
}

type VerifyLoginOTPInput struct {
	Phone      string `json:"phone"`
	Code       string `json:"code"`
	RememberMe bool   `json:"remember_me"`
}

type ForgotInput struct {
	Channel    string `json:"channel"` // email | whatsapp
	Identifier string `json:"identifier"`
}

type VerifyResetOTPInput struct {
	Channel    string `json:"channel"`
	Identifier string `json:"identifier"`
	Code       string `json:"code"`
}

type ResetTokenResult struct {
	ResetToken string `json:"reset_token"`
	ExpiresIn  int    `json:"expires_in"`
}

type ResetPasswordInput struct {
	ResetToken      string `json:"reset_token"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

type RefreshInput struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutInput struct {
	RefreshToken string `json:"refresh_token"`
	All          bool   `json:"all"`
}

// ---------- helpers ----------

func (s *Service) internal(err error) error {
	s.log.Error("internal error", "err", err)
	return domain.ErrInternal
}

func validation(d map[string]string) error { return domain.ErrValidation.WithDetails(d) }

func isLocked(u *domain.User, now time.Time) bool {
	return u.LockedUntil != nil && now.Before(*u.LockedUntil)
}

func (s *Service) lockedErr(until time.Time, now time.Time) error {
	secs := int(until.Sub(now).Seconds()) + 1
	return domain.ErrAccountLocked.With("retry_after_seconds", secs)
}

func view(u *domain.User) UserView {
	return UserView{ID: u.ID, FullName: u.FullName, Email: u.Email, Phone: u.Phone, CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt}
}

func (s *Service) issueSession(ctx context.Context, u *domain.User, remember bool, meta ClientMeta, keepExp *time.Time) (*AuthResult, error) {
	now := s.Now()
	access, err := s.tokens.NewAccess(u.ID, now, s.cfg.AccessTTL)
	if err != nil {
		return nil, s.internal(err)
	}
	plain, hash, err := security.NewOpaqueToken()
	if err != nil {
		return nil, s.internal(err)
	}
	exp := now.Add(s.cfg.SessionTTL)
	if remember {
		exp = now.Add(s.cfg.RememberTTL)
	}
	if keepExp != nil {
		exp = *keepExp
	}
	ua := meta.UserAgent
	if len(ua) > 255 {
		ua = ua[:255]
	}
	rt := &domain.RefreshToken{ID: security.NewUUID(), UserID: u.ID, TokenHash: hash, ExpiresAt: exp, IP: meta.IP, UserAgent: ua, CreatedAt: now}
	if err := s.store.CreateRefreshToken(ctx, rt); err != nil {
		return nil, s.internal(err)
	}
	return &AuthResult{AccessToken: access, RefreshToken: plain, TokenType: "Bearer",
		ExpiresIn: int(s.cfg.AccessTTL.Seconds()), User: view(u)}, nil
}

// ---------- Register ----------

func (s *Service) Register(ctx context.Context, in RegisterInput, meta ClientMeta) (*AuthResult, error) {
	d := map[string]string{}
	name := strings.TrimSpace(in.FullName)
	if !validName(name) {
		d["full_name"] = "Nama lengkap tidak valid (2-100 karakter, hanya huruf)."
	}
	email, ok := normalizeEmail(in.Email)
	if !ok {
		d["email"] = "Format email tidak valid."
	}
	phone, ok := normalizePhone(in.Phone)
	if !ok {
		d["phone"] = "Nomor WhatsApp tidak valid (contoh: +6281234567890)."
	}
	if p := passwordProblems(in.Password); len(p) > 0 {
		d["password"] = "Kata sandi belum memenuhi: " + strings.Join(p, "; ") + "."
	}
	if in.ConfirmPassword != in.Password {
		d["confirm_password"] = "Konfirmasi kata sandi tidak cocok."
	}
	if !in.AcceptTerms {
		d["accept_terms"] = "Anda harus menyetujui Syarat & Ketentuan dan Kebijakan Privasi."
	}
	if len(d) > 0 {
		return nil, validation(d)
	}

	// Cek duplikat: layar register menampilkan error email & WA sekaligus.
	taken := map[string]string{}
	if _, err := s.store.GetUserByEmail(ctx, email); err == nil {
		taken["email"] = "Email ini sudah terdaftar. Silakan gunakan email lain atau masuk."
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, s.internal(err)
	}
	if _, err := s.store.GetUserByPhone(ctx, phone); err == nil {
		taken["phone"] = "Nomor WhatsApp ini sudah terdaftar di akun aktif."
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, s.internal(err)
	}
	if len(taken) > 0 {
		return nil, domain.ErrConflict.WithDetails(taken)
	}

	hash, err := security.HashPassword(in.Password, s.cfg.BcryptCost)
	if err != nil {
		return nil, s.internal(err)
	}
	now := s.Now()
	u := &domain.User{ID: security.NewUUID(), FullName: name, Email: email, Phone: phone,
		PasswordHash: hash, AcceptedTermsAt: now, CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateUser(ctx, u); err != nil {
		switch {
		case errors.Is(err, store.ErrEmailTaken):
			return nil, domain.ErrConflict.WithDetails(map[string]string{"email": "Email ini sudah terdaftar. Silakan gunakan email lain atau masuk."})
		case errors.Is(err, store.ErrPhoneTaken):
			return nil, domain.ErrConflict.WithDetails(map[string]string{"phone": "Nomor WhatsApp ini sudah terdaftar di akun aktif."})
		}
		return nil, s.internal(err)
	}
	return s.issueSession(ctx, u, false, meta, nil)
}

// ---------- Login email + password ----------

func (s *Service) Login(ctx context.Context, in LoginInput, meta ClientMeta) (*AuthResult, error) {
	d := map[string]string{}
	ident := strings.ToLower(strings.TrimSpace(in.Identifier))
	if ident == "" {
		d["identifier"] = "Email wajib diisi."
	}
	if in.Password == "" {
		d["password"] = "Kata sandi wajib diisi."
	}
	if len(d) > 0 {
		return nil, validation(d)
	}
	u, err := s.store.GetUserByEmail(ctx, ident)
	if errors.Is(err, store.ErrNotFound) {
		security.CheckPassword(s.dummy, in.Password)
		return nil, domain.ErrInvalidCredentials.WithMessage("Kombinasi email atau kata sandi tidak cocok. Silakan periksa kembali.")
	}
	if err != nil {
		return nil, s.internal(err)
	}
	now := s.Now()
	if isLocked(u, now) {
		return nil, s.lockedErr(*u.LockedUntil, now)
	}
	if len(in.Password) > 72 || !security.CheckPassword(u.PasswordHash, in.Password) {
		failed, until, err := s.store.RegisterFailedLogin(ctx, u.ID, s.cfg.MaxLoginAttempts, s.cfg.LockDuration, now)
		if err != nil {
			return nil, s.internal(err)
		}
		if until != nil {
			return nil, s.lockedErr(*until, now)
		}
		return nil, domain.ErrInvalidCredentials.
			WithMessage("Kombinasi email atau kata sandi tidak cocok. Silakan periksa kembali.").
			With("attempts_remaining", s.cfg.MaxLoginAttempts-failed)
	}
	if err := s.store.MarkLoginSuccess(ctx, u.ID, now); err != nil {
		return nil, s.internal(err)
	}
	return s.issueSession(ctx, u, in.RememberMe, meta, nil)
}

// ---------- OTP core ----------

func (s *Service) fakeSent(ch domain.OTPChannel, masked string) *OTPSent {
	return &OTPSent{Channel: string(ch), Destination: masked,
		ExpiresIn: int(s.cfg.OTPTTL.Seconds()), ResendAvailableIn: int(s.cfg.OTPResendCooldown.Seconds())}
}

func (s *Service) issueOTP(ctx context.Context, u *domain.User, purpose domain.OTPPurpose, ch domain.OTPChannel, target, masked string) (*OTPSent, error) {
	now := s.Now()
	last, err := s.store.LatestOTP(ctx, target, purpose)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, s.internal(err)
	}
	if last != nil {
		if wait := last.CreatedAt.Add(s.cfg.OTPResendCooldown); now.Before(wait) {
			secs := int(wait.Sub(now).Seconds()) + 1
			return nil, domain.ErrOTPCooldown.With("retry_after_seconds", secs)
		}
	}
	code, err := security.NewOTPCode()
	if err != nil {
		return nil, s.internal(err)
	}
	otp := &domain.OTP{ID: security.NewUUID(), UserID: u.ID, Purpose: purpose, Channel: ch, Target: target,
		CodeHash:  security.HashOTP(s.cfg.OTPSecret, target, string(purpose), code),
		ExpiresAt: now.Add(s.cfg.OTPTTL), CreatedAt: now}
	if err := s.store.CreateOTP(ctx, otp); err != nil {
		return nil, s.internal(err)
	}
	if err := s.send.Send(ctx, notify.OTPMessage{Channel: ch, Target: target, Code: code, TTL: s.cfg.OTPTTL}); err != nil {
		s.log.Error("kirim OTP gagal", "err", err, "channel", ch)
		// OTP yang tidak terkirim tidak boleh memblokir resend
		_, _ = s.store.ConsumeOTP(ctx, otp.ID, now)
		return nil, domain.ErrDeliveryFailed
	}
	return s.fakeSent(ch, masked), nil
}

// verifyOTP memvalidasi kode dan meng-consume-nya (sekali pakai). Mengembalikan user pemilik OTP.
func (s *Service) verifyOTP(ctx context.Context, target string, purpose domain.OTPPurpose, code string) (*domain.User, error) {
	otp, err := s.store.LatestOTP(ctx, target, purpose)
	if errors.Is(err, store.ErrNotFound) {
		return nil, domain.ErrOTPExpired
	}
	if err != nil {
		return nil, s.internal(err)
	}
	now := s.Now()
	if otp.ConsumedAt != nil || !now.Before(otp.ExpiresAt) {
		return nil, domain.ErrOTPExpired
	}
	u, err := s.store.GetUserByID(ctx, otp.UserID)
	if err != nil {
		return nil, s.internal(err)
	}
	if purpose == domain.PurposeLoginWhatsApp && isLocked(u, now) {
		return nil, s.lockedErr(*u.LockedUntil, now)
	}
	want := security.HashOTP(s.cfg.OTPSecret, target, string(purpose), code)
	if !security.EqualHash(otp.CodeHash, want) {
		n, err := s.store.IncrementOTPAttempts(ctx, otp.ID)
		if err != nil {
			return nil, s.internal(err)
		}
		remaining := s.cfg.OTPMaxAttempts - n
		if remaining <= 0 {
			_, _ = s.store.ConsumeOTP(ctx, otp.ID, now) // OTP hangus
			if purpose == domain.PurposeLoginWhatsApp {
				until := now.Add(s.cfg.LockDuration)
				if err := s.store.LockUser(ctx, u.ID, until); err != nil {
					return nil, s.internal(err)
				}
				return nil, s.lockedErr(until, now)
			}
			return nil, domain.ErrOTPExpired.WithMessage("Percobaan verifikasi habis. Silakan minta kode baru.")
		}
		return nil, domain.ErrOTPInvalid.With("attempts_remaining", remaining)
	}
	ok, err := s.store.ConsumeOTP(ctx, otp.ID, now)
	if err != nil {
		return nil, s.internal(err)
	}
	if !ok {
		return nil, domain.ErrOTPExpired
	}
	return u, nil
}

// ---------- Login WhatsApp + OTP ----------

func (s *Service) RequestLoginOTP(ctx context.Context, in PhoneInput, _ ClientMeta) (*OTPSent, error) {
	phone, ok := normalizePhone(in.Phone)
	if !ok {
		return nil, validation(map[string]string{"phone": "Nomor WhatsApp tidak valid (contoh: +6281234567890)."})
	}
	masked := maskPhone(phone)
	u, err := s.store.GetUserByPhone(ctx, phone)
	if errors.Is(err, store.ErrNotFound) {
		return s.fakeSent(domain.ChannelWhatsApp, masked), nil // anti user-enumeration
	}
	if err != nil {
		return nil, s.internal(err)
	}
	if now := s.Now(); isLocked(u, now) {
		return nil, s.lockedErr(*u.LockedUntil, now)
	}
	return s.issueOTP(ctx, u, domain.PurposeLoginWhatsApp, domain.ChannelWhatsApp, phone, masked)
}

func (s *Service) VerifyLoginOTP(ctx context.Context, in VerifyLoginOTPInput, meta ClientMeta) (*AuthResult, error) {
	d := map[string]string{}
	phone, ok := normalizePhone(in.Phone)
	if !ok {
		d["phone"] = "Nomor WhatsApp tidak valid."
	}
	if !validCode(in.Code) {
		d["code"] = "Kode OTP harus 6 digit angka."
	}
	if len(d) > 0 {
		return nil, validation(d)
	}
	u, err := s.verifyOTP(ctx, phone, domain.PurposeLoginWhatsApp, in.Code)
	if err != nil {
		return nil, err
	}
	if err := s.store.MarkLoginSuccess(ctx, u.ID, s.Now()); err != nil {
		return nil, s.internal(err)
	}
	return s.issueSession(ctx, u, in.RememberMe, meta, nil)
}

// ---------- Lupa password ----------

func (s *Service) resolveTarget(channel, identifier string) (domain.OTPChannel, string, string, map[string]string) {
	switch channel {
	case "email":
		e, ok := normalizeEmail(identifier)
		if !ok {
			return "", "", "", map[string]string{"identifier": "Format email tidak valid."}
		}
		return domain.ChannelEmail, e, maskEmail(e), nil
	case "whatsapp":
		p, ok := normalizePhone(identifier)
		if !ok {
			return "", "", "", map[string]string{"identifier": "Nomor WhatsApp tidak valid."}
		}
		return domain.ChannelWhatsApp, p, maskPhone(p), nil
	}
	return "", "", "", map[string]string{"channel": "Metode verifikasi harus 'email' atau 'whatsapp'."}
}

func (s *Service) userByTarget(ctx context.Context, ch domain.OTPChannel, target string) (*domain.User, error) {
	if ch == domain.ChannelEmail {
		return s.store.GetUserByEmail(ctx, target)
	}
	return s.store.GetUserByPhone(ctx, target)
}

func (s *Service) ForgotPassword(ctx context.Context, in ForgotInput, _ ClientMeta) (*OTPSent, error) {
	ch, target, masked, d := s.resolveTarget(in.Channel, in.Identifier)
	if d != nil {
		return nil, validation(d)
	}
	u, err := s.userByTarget(ctx, ch, target)
	if errors.Is(err, store.ErrNotFound) {
		return s.fakeSent(ch, masked), nil // anti user-enumeration
	}
	if err != nil {
		return nil, s.internal(err)
	}
	return s.issueOTP(ctx, u, domain.PurposeResetPassword, ch, target, masked)
}

func (s *Service) VerifyResetOTP(ctx context.Context, in VerifyResetOTPInput, _ ClientMeta) (*ResetTokenResult, error) {
	ch, target, _, d := s.resolveTarget(in.Channel, in.Identifier)
	if d == nil && !validCode(in.Code) {
		d = map[string]string{"code": "Kode OTP harus 6 digit angka."}
	}
	if d != nil {
		return nil, validation(d)
	}
	_ = ch
	u, err := s.verifyOTP(ctx, target, domain.PurposeResetPassword, in.Code)
	if err != nil {
		return nil, err
	}
	plain, hash, err := security.NewOpaqueToken()
	if err != nil {
		return nil, s.internal(err)
	}
	now := s.Now()
	rt := &domain.ResetToken{ID: security.NewUUID(), UserID: u.ID, TokenHash: hash, ExpiresAt: now.Add(s.cfg.ResetTokenTTL), CreatedAt: now}
	if err := s.store.CreateResetToken(ctx, rt); err != nil {
		return nil, s.internal(err)
	}
	return &ResetTokenResult{ResetToken: plain, ExpiresIn: int(s.cfg.ResetTokenTTL.Seconds())}, nil
}

func (s *Service) ResetPassword(ctx context.Context, in ResetPasswordInput, meta ClientMeta) (*AuthResult, error) {
	if in.ResetToken == "" {
		return nil, validation(map[string]string{"reset_token": "Reset token wajib diisi."})
	}
	rt, err := s.store.GetResetToken(ctx, security.HashToken(in.ResetToken))
	if errors.Is(err, store.ErrNotFound) {
		return nil, domain.ErrResetTokenInvalid
	}
	if err != nil {
		return nil, s.internal(err)
	}
	now := s.Now()
	if rt.UsedAt != nil || !now.Before(rt.ExpiresAt) {
		return nil, domain.ErrResetTokenInvalid
	}
	d := map[string]string{}
	if p := passwordProblems(in.NewPassword); len(p) > 0 {
		d["new_password"] = "Kata sandi belum memenuhi: " + strings.Join(p, "; ") + "."
	}
	if in.ConfirmPassword != in.NewPassword {
		d["confirm_password"] = "Konfirmasi kata sandi tidak cocok."
	}
	if len(d) > 0 {
		return nil, validation(d)
	}
	hashes, err := s.store.RecentPasswordHashes(ctx, rt.UserID, s.cfg.PasswordHistoryDepth)
	if err != nil {
		return nil, s.internal(err)
	}
	for _, h := range hashes {
		if security.CheckPassword(h, in.NewPassword) {
			return nil, domain.ErrPasswordReused.WithDetails(map[string]string{"new_password": domain.ErrPasswordReused.Message})
		}
	}
	newHash, err := security.HashPassword(in.NewPassword, s.cfg.BcryptCost)
	if err != nil {
		return nil, s.internal(err)
	}
	if err := s.store.ResetPassword(ctx, rt.UserID, rt.ID, newHash, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, domain.ErrResetTokenInvalid
		}
		return nil, s.internal(err)
	}
	u, err := s.store.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, s.internal(err)
	}
	_ = s.store.MarkLoginSuccess(ctx, u.ID, now)
	return s.issueSession(ctx, u, false, meta, nil) // "Simpan Kata Sandi & Masuk"
}

// ---------- Session ----------

func (s *Service) Refresh(ctx context.Context, in RefreshInput, meta ClientMeta) (*AuthResult, error) {
	if in.RefreshToken == "" {
		return nil, validation(map[string]string{"refresh_token": "Refresh token wajib diisi."})
	}
	rt, err := s.store.GetRefreshToken(ctx, security.HashToken(in.RefreshToken))
	if errors.Is(err, store.ErrNotFound) {
		return nil, domain.ErrInvalidToken
	}
	if err != nil {
		return nil, s.internal(err)
	}
	now := s.Now()
	if rt.RevokedAt != nil {
		// token lama dipakai ulang -> kemungkinan dicuri: cabut semua sesi user
		_ = s.store.RevokeUserRefreshTokens(ctx, rt.UserID, now)
		return nil, domain.ErrInvalidToken
	}
	if !now.Before(rt.ExpiresAt) {
		return nil, domain.ErrInvalidToken
	}
	ok, err := s.store.RevokeRefreshToken(ctx, rt.ID, now)
	if err != nil {
		return nil, s.internal(err)
	}
	if !ok {
		return nil, domain.ErrInvalidToken
	}
	u, err := s.store.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, s.internal(err)
	}
	return s.issueSession(ctx, u, false, meta, &rt.ExpiresAt)
}

func (s *Service) Logout(ctx context.Context, userID string, in LogoutInput) error {
	now := s.Now()
	if in.All {
		if err := s.store.RevokeUserRefreshTokens(ctx, userID, now); err != nil {
			return s.internal(err)
		}
		return nil
	}
	if in.RefreshToken == "" {
		return validation(map[string]string{"refresh_token": "Refresh token wajib diisi (atau set all=true)."})
	}
	rt, err := s.store.GetRefreshToken(ctx, security.HashToken(in.RefreshToken))
	if errors.Is(err, store.ErrNotFound) || (err == nil && rt.UserID != userID) {
		return nil // idempotent
	}
	if err != nil {
		return s.internal(err)
	}
	if _, err := s.store.RevokeRefreshToken(ctx, rt.ID, now); err != nil {
		return s.internal(err)
	}
	return nil
}

func (s *Service) Authenticate(token string) (string, error) {
	id, err := s.tokens.ParseAccess(token, s.Now())
	if err != nil {
		return "", domain.ErrUnauthorized
	}
	return id, nil
}

func (s *Service) Me(ctx context.Context, userID string) (*UserView, error) {
	u, err := s.store.GetUserByID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, domain.ErrUnauthorized
	}
	if err != nil {
		return nil, s.internal(err)
	}
	v := view(u)
	return &v, nil
}

func (s *Service) Cleanup(ctx context.Context) error { return s.store.DeleteExpired(ctx, s.Now()) }
