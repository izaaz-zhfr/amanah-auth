package handler_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"amanah-auth/internal/config"
	"amanah-auth/internal/handler"
	"amanah-auth/internal/notify"
	"amanah-auth/internal/service"
	"amanah-auth/internal/store"

	_ "github.com/lib/pq"
)

// newStore memakai PostgreSQL bila TEST_DATABASE_URL di-set (schema harus sudah dimigrasi), selain itu in-memory.
func newStore(t *testing.T) store.Store {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		return store.NewMemory()
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`TRUNCATE users, otp_codes, refresh_tokens, password_reset_tokens, password_histories CASCADE`); err != nil {
		t.Fatal(err)
	}
	pg, err := store.NewPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	return pg
}

type env struct {
	t    *testing.T
	srv  http.Handler
	rec  *notify.Recorder
	mu   sync.Mutex
	time time.Time
}

func newEnv(t *testing.T) *env {
	cfg := config.Default()
	cfg.BcryptCost = 4
	cfg.RateLimitPerMin = 0
	e := &env{t: t, rec: &notify.Recorder{}, time: time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(cfg, newStore(t), e.rec, log)
	svc.Now = func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.time }
	e.srv = handler.New(svc, log, 0).Routes()
	return e
}

func (e *env) advance(d time.Duration) { e.mu.Lock(); e.time = e.time.Add(d); e.mu.Unlock() }

type resp struct {
	Status int
	Body   map[string]any
}

func (r resp) data() map[string]any { d, _ := r.Body["data"].(map[string]any); return d }
func (r resp) errObj() map[string]any {
	d, _ := r.Body["error"].(map[string]any)
	return d
}
func (r resp) code() string { s, _ := r.errObj()["code"].(string); return s }
func (r resp) meta(k string) any {
	m, _ := r.errObj()["meta"].(map[string]any)
	return m[k]
}

func (e *env) call(method, path string, body any, token string) resp {
	var rd io.Reader
	if s, ok := body.(string); ok {
		rd = bytes.NewBufferString(s)
	} else if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "192.0.2.1:5555"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, req)
	out := resp{Status: w.Code, Body: map[string]any{}}
	_ = json.Unmarshal(w.Body.Bytes(), &out.Body)
	return out
}

func m(kv ...any) map[string]any {
	o := map[string]any{}
	for i := 0; i < len(kv); i += 2 {
		o[kv[i].(string)] = kv[i+1]
	}
	return o
}

const (
	pw    = "Rahasia#2026"
	email = "budi.santoso@gmail.com"
	phone = "+6281234567890"
)

func (e *env) register() resp {
	return e.call("POST", "/api/v1/auth/register", m("full_name", "Budi Santoso", "email", email, "phone", "0812-3456-7890",
		"password", pw, "confirm_password", pw, "accept_terms", true), "")
}

func (e *env) lastCode() string {
	msg, ok := e.rec.Last()
	if !ok {
		e.t.Fatal("tidak ada OTP terkirim")
	}
	return msg.Code
}

func eq[T comparable](t *testing.T, got, want T, what string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

func TestRegisterAndMe(t *testing.T) {
	e := newEnv(t)
	r := e.register()
	eq(t, r.Status, 201, "register status")
	tok, _ := r.data()["access_token"].(string)
	if tok == "" || r.data()["refresh_token"] == "" {
		t.Fatal("token kosong")
	}
	eq(t, r.data()["user"].(map[string]any)["phone"], any(phone), "phone ternormalisasi")

	me := e.call("GET", "/api/v1/users/me", nil, tok)
	eq(t, me.Status, 200, "me")
	eq(t, me.data()["email"], any(email), "me email")
	eq(t, e.call("GET", "/api/v1/users/me", nil, "").Status, 401, "tanpa token")
	eq(t, e.call("GET", "/api/v1/users/me", nil, tok+"x").Status, 401, "token rusak")

	// duplikat: email & WA keduanya dilaporkan
	dup := e.register()
	eq(t, dup.Status, 409, "duplikat")
	d := dup.errObj()["details"].(map[string]any)
	if d["email"] == nil || d["phone"] == nil {
		t.Fatalf("detail duplikat kurang: %v", d)
	}
}

func TestRegisterValidation(t *testing.T) {
	e := newEnv(t)
	r := e.call("POST", "/api/v1/auth/register", m("full_name", "B", "email", "bukan-email", "phone", "123",
		"password", "lemah", "confirm_password", "beda", "accept_terms", false), "")
	eq(t, r.Status, 422, "status")
	eq(t, r.code(), "validation_failed", "code")
	d := r.errObj()["details"].(map[string]any)
	for _, k := range []string{"full_name", "email", "phone", "password", "confirm_password", "accept_terms"} {
		if d[k] == nil {
			t.Errorf("detail %s hilang", k)
		}
	}
	eq(t, e.call("POST", "/api/v1/auth/register", "{bad json", "").Status, 400, "json rusak")
	eq(t, e.call("POST", "/api/v1/auth/register", m("foo", "bar"), "").Status, 400, "field tak dikenal")
	eq(t, e.call("POST", "/api/v1/auth/register", "", "").Status, 400, "body kosong")
	eq(t, e.call("GET", "/api/v1/tidak-ada", nil, "").Status, 404, "404")
}

func TestLoginEmailAndLockout(t *testing.T) {
	e := newEnv(t)
	e.register()
	ok := e.call("POST", "/api/v1/auth/login", m("identifier", "BUDI.santoso@gmail.com", "password", pw, "remember_me", true), "")
	eq(t, ok.Status, 200, "login ok")

	eq(t, e.call("POST", "/api/v1/auth/login", m("identifier", "x@y.com", "password", pw), "").code(), "invalid_credentials", "user tak ada")
	eq(t, e.call("POST", "/api/v1/auth/login", m("identifier", "", "password", ""), "").Status, 422, "kosong")

	for i, want := range []float64{4, 3, 2, 1} {
		r := e.call("POST", "/api/v1/auth/login", m("identifier", email, "password", "Salah#123"), "")
		eq(t, r.Status, 401, "salah ke-"+string(rune('1'+i)))
		eq(t, r.meta("attempts_remaining"), any(want), "attempts_remaining")
	}
	r := e.call("POST", "/api/v1/auth/login", m("identifier", email, "password", "Salah#123"), "")
	eq(t, r.Status, 423, "terkunci")
	eq(t, e.call("POST", "/api/v1/auth/login", m("identifier", email, "password", pw), "").Status, 423, "benar tapi terkunci")
	e.advance(16 * time.Minute)
	eq(t, e.call("POST", "/api/v1/auth/login", m("identifier", email, "password", pw), "").Status, 200, "lock kedaluwarsa")
}

func TestWhatsAppOTPLogin(t *testing.T) {
	e := newEnv(t)
	e.register()

	// nomor tak terdaftar: respons sama, tidak ada OTP terkirim
	r := e.call("POST", "/api/v1/auth/login/whatsapp/otp/request", m("phone", "+6281999999999"), "")
	eq(t, r.Status, 200, "unregistered generic")
	eq(t, e.rec.Count(), 0, "tidak kirim OTP")
	eq(t, e.call("POST", "/api/v1/auth/login/whatsapp/otp/request", m("phone", "abc"), "").Status, 422, "format salah")

	r = e.call("POST", "/api/v1/auth/login/whatsapp/otp/request", m("phone", phone), "")
	eq(t, r.Status, 200, "request")
	eq(t, r.data()["destination"], any("+62 812-****-7890"), "masked")
	code := e.lastCode()

	// resend langsung -> cooldown
	cd := e.call("POST", "/api/v1/auth/login/whatsapp/otp/request", m("phone", phone), "")
	eq(t, cd.Status, 429, "cooldown")
	eq(t, e.rec.Count(), 1, "tidak kirim ulang")

	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	w := e.call("POST", "/api/v1/auth/login/whatsapp/otp/verify", m("phone", phone, "code", wrong), "")
	eq(t, w.Status, 400, "salah")
	eq(t, w.meta("attempts_remaining"), any(float64(4)), "sisa")
	eq(t, e.call("POST", "/api/v1/auth/login/whatsapp/otp/verify", m("phone", phone, "code", "12ab"), "").Status, 422, "format kode")

	ok := e.call("POST", "/api/v1/auth/login/whatsapp/otp/verify", m("phone", phone, "code", code, "remember_me", true), "")
	eq(t, ok.Status, 200, "verify ok")
	if ok.data()["access_token"] == nil {
		t.Fatal("tidak ada token")
	}
	// replay ditolak
	eq(t, e.call("POST", "/api/v1/auth/login/whatsapp/otp/verify", m("phone", phone, "code", code), "").code(), "otp_expired", "replay")

	// resend setelah cooldown, lalu kedaluwarsa
	e.advance(61 * time.Second)
	eq(t, e.call("POST", "/api/v1/auth/login/whatsapp/otp/request", m("phone", phone), "").Status, 200, "resend")
	code2 := e.lastCode()
	e.advance(6 * time.Minute)
	eq(t, e.call("POST", "/api/v1/auth/login/whatsapp/otp/verify", m("phone", phone, "code", code2), "").code(), "otp_expired", "expired")

	// 5x salah -> akun dibekukan
	e.advance(61 * time.Second)
	e.call("POST", "/api/v1/auth/login/whatsapp/otp/request", m("phone", phone), "")
	code3 := e.lastCode()
	wrong = "000000"
	if code3 == wrong {
		wrong = "111111"
	}
	var last resp
	for i := 0; i < 5; i++ {
		last = e.call("POST", "/api/v1/auth/login/whatsapp/otp/verify", m("phone", phone, "code", wrong), "")
	}
	eq(t, last.Status, 423, "dibekukan")
	eq(t, e.call("POST", "/api/v1/auth/login/whatsapp/otp/verify", m("phone", phone, "code", code3), "").code(), "otp_expired", "OTP hangus setelah percobaan habis")
	e.advance(61 * time.Second)
	eq(t, e.call("POST", "/api/v1/auth/login/whatsapp/otp/request", m("phone", phone), "").Status, 423, "minta OTP saat beku")
	e.advance(16 * time.Minute)
	eq(t, e.call("POST", "/api/v1/auth/login/whatsapp/otp/request", m("phone", phone), "").Status, 200, "beku berakhir")
}

func TestOTPDeliveryFailure(t *testing.T) {
	e := newEnv(t)
	e.register()
	e.rec.Fail = true
	eq(t, e.call("POST", "/api/v1/auth/login/whatsapp/otp/request", m("phone", phone), "").Status, 502, "provider down")
	e.rec.Fail = false
	eq(t, e.call("POST", "/api/v1/auth/login/whatsapp/otp/request", m("phone", phone), "").Status, 429, "cooldown tetap berlaku")
	e.advance(61 * time.Second)
	eq(t, e.call("POST", "/api/v1/auth/login/whatsapp/otp/request", m("phone", phone), "").Status, 200, "retry setelah cooldown")
}

func TestForgotPasswordFlow(t *testing.T) {
	e := newEnv(t)
	reg := e.register()
	oldRefresh := reg.data()["refresh_token"].(string)

	// email tak terdaftar -> generik
	eq(t, e.call("POST", "/api/v1/auth/password/forgot", m("channel", "email", "identifier", "nobody@x.com"), "").Status, 200, "generik")
	eq(t, e.rec.Count(), 0, "tidak kirim")
	eq(t, e.call("POST", "/api/v1/auth/password/forgot", m("channel", "sms", "identifier", "x"), "").Status, 422, "channel salah")

	f := e.call("POST", "/api/v1/auth/password/forgot", m("channel", "email", "identifier", email), "")
	eq(t, f.Status, 200, "forgot")
	eq(t, f.data()["destination"], any("bud***@gmail.com"), "masked email")
	code := e.lastCode()

	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	eq(t, e.call("POST", "/api/v1/auth/password/otp/verify", m("channel", "email", "identifier", email, "code", wrong), "").Status, 400, "otp salah")
	v := e.call("POST", "/api/v1/auth/password/otp/verify", m("channel", "email", "identifier", email, "code", code), "")
	eq(t, v.Status, 200, "otp ok")
	rt := v.data()["reset_token"].(string)

	eq(t, e.call("POST", "/api/v1/auth/password/reset", m("reset_token", "ngawur", "new_password", "Baru#Pass2026", "confirm_password", "Baru#Pass2026"), "").code(), "reset_token_invalid", "token ngawur")
	eq(t, e.call("POST", "/api/v1/auth/password/reset", m("reset_token", rt, "new_password", "lemah", "confirm_password", "lemah"), "").Status, 422, "lemah")
	eq(t, e.call("POST", "/api/v1/auth/password/reset", m("reset_token", rt, "new_password", pw, "confirm_password", pw), "").code(), "password_reused", "pakai password lama")

	newPw := "Baru#Pass2026"
	rs := e.call("POST", "/api/v1/auth/password/reset", m("reset_token", rt, "new_password", newPw, "confirm_password", newPw), "")
	eq(t, rs.Status, 200, "reset ok")
	if rs.data()["access_token"] == nil {
		t.Fatal("harus auto-login")
	}
	// token sekali pakai
	eq(t, e.call("POST", "/api/v1/auth/password/reset", m("reset_token", rt, "new_password", "Lain#Pass2026", "confirm_password", "Lain#Pass2026"), "").code(), "reset_token_invalid", "reuse token")
	// sesi lama dicabut, password lama tak berlaku
	eq(t, e.call("POST", "/api/v1/auth/token/refresh", m("refresh_token", oldRefresh), "").Status, 401, "refresh lama dicabut")
	eq(t, e.call("POST", "/api/v1/auth/login", m("identifier", email, "password", pw), "").Status, 401, "password lama")
	eq(t, e.call("POST", "/api/v1/auth/login", m("identifier", email, "password", newPw), "").Status, 200, "password baru")
}

func TestForgotPasswordViaWhatsApp(t *testing.T) {
	e := newEnv(t)
	e.register()
	eq(t, e.call("POST", "/api/v1/auth/password/forgot", m("channel", "whatsapp", "identifier", "081234567890"), "").Status, 200, "forgot wa")
	msg, _ := e.rec.Last()
	eq(t, string(msg.Channel), "whatsapp", "channel")
	v := e.call("POST", "/api/v1/auth/password/otp/verify", m("channel", "whatsapp", "identifier", phone, "code", msg.Code), "")
	eq(t, v.Status, 200, "verify wa")
}

func TestRefreshRotationAndLogout(t *testing.T) {
	e := newEnv(t)
	reg := e.register()
	access := reg.data()["access_token"].(string)
	r1 := reg.data()["refresh_token"].(string)

	n := e.call("POST", "/api/v1/auth/token/refresh", m("refresh_token", r1), "")
	eq(t, n.Status, 200, "refresh")
	r2 := n.data()["refresh_token"].(string)
	if r1 == r2 {
		t.Fatal("refresh token harus dirotasi")
	}
	// reuse token lama -> semua sesi dicabut
	eq(t, e.call("POST", "/api/v1/auth/token/refresh", m("refresh_token", r1), "").Status, 401, "reuse")
	eq(t, e.call("POST", "/api/v1/auth/token/refresh", m("refresh_token", r2), "").Status, 401, "sesi dicabut")

	// access token kedaluwarsa
	e.advance(16 * time.Minute)
	eq(t, e.call("GET", "/api/v1/users/me", nil, access).Status, 401, "access expired")

	// logout
	lg := e.call("POST", "/api/v1/auth/login", m("identifier", email, "password", pw), "")
	tok, rt := lg.data()["access_token"].(string), lg.data()["refresh_token"].(string)
	eq(t, e.call("POST", "/api/v1/auth/logout", m("refresh_token", rt), "").Status, 401, "logout tanpa auth")
	eq(t, e.call("POST", "/api/v1/auth/logout", m("refresh_token", rt), tok).Status, 200, "logout")
	eq(t, e.call("POST", "/api/v1/auth/token/refresh", m("refresh_token", rt), "").Status, 401, "refresh setelah logout")
}

func TestRateLimit(t *testing.T) {
	cfg := config.Default()
	cfg.BcryptCost = 4
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(cfg, store.NewMemory(), &notify.Recorder{}, log)
	srv := handler.New(svc, log, 3).Routes()
	var last int
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBufferString(`{"identifier":"a@b.co","password":"x"}`))
		req.RemoteAddr = "192.0.2.9:1"
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		last = w.Code
	}
	eq(t, last, 429, "rate limit")
}
