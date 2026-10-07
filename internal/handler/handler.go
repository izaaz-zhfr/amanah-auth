package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"amanah-auth/docs"
	"amanah-auth/internal/domain"
	"amanah-auth/internal/service"
)

type Handler struct {
	svc        *service.Service
	log        *slog.Logger
	ratePerMin int
}

func New(svc *service.Service, log *slog.Logger, ratePerMin int) *Handler {
	return &Handler{svc: svc, log: log, ratePerMin: ratePerMin}
}

type envelope struct {
	Success bool             `json:"success"`
	Message string           `json:"message,omitempty"`
	Data    any              `json:"data,omitempty"`
	Error   *domain.AppError `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) ok(w http.ResponseWriter, status int, msg string, data any) {
	writeJSON(w, status, envelope{Success: true, Message: msg, Data: data})
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *domain.AppError
	if !errors.As(err, &ae) {
		h.log.Error("unhandled error", "err", err, "path", r.URL.Path)
		ae = domain.ErrInternal
	}
	if v, ok := ae.Meta["retry_after_seconds"].(int); ok {
		w.Header().Set("Retry-After", strconv.Itoa(v))
	}
	writeJSON(w, ae.Status, envelope{Success: false, Error: ae})
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			writeJSON(w, http.StatusRequestEntityTooLarge, envelope{Error: domain.NewError(http.StatusRequestEntityTooLarge, "payload_too_large", "Ukuran request terlalu besar.")})
		case errors.Is(err, io.EOF):
			h.fail(w, r, domain.ErrBadRequest.WithMessage("Body request kosong."))
		default:
			h.fail(w, r, domain.NewError(http.StatusBadRequest, "invalid_json", "Format JSON tidak valid atau ada field yang tidak dikenal."))
		}
		return false
	}
	if dec.More() {
		h.fail(w, r, domain.NewError(http.StatusBadRequest, "invalid_json", "Body hanya boleh berisi satu objek JSON."))
		return false
	}
	return true
}

func meta(r *http.Request) service.ClientMeta {
	return service.ClientMeta{IP: clientIP(r), UserAgent: r.UserAgent()}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handle membungkus method service dengan signature (ctx, In, meta) -> (Out, error).
func handle[In any, Out any](h *Handler, status int, msg string, fn func(context.Context, In, service.ClientMeta) (Out, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in In
		if !h.decode(w, r, &in) {
			return
		}
		out, err := fn(r.Context(), in, meta(r))
		if err != nil {
			h.fail(w, r, err)
			return
		}
		h.ok(w, status, msg, out)
	}
}

type ctxKey struct{}

func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		scheme, tok, found := strings.Cut(hdr, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || tok == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="amanah"`)
			h.fail(w, r, domain.ErrUnauthorized)
			return
		}
		id, err := h.svc.Authenticate(strings.TrimSpace(tok))
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			h.fail(w, r, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	}
}

func userID(r *http.Request) string { id, _ := r.Context().Value(ctxKey{}).(string); return id }

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	const p = "/api/v1"

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		h.ok(w, http.StatusOK, "ok", map[string]string{"status": "up"})
	})
	mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(docs.OpenAPI)
	})
	mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, swaggerHTML)
	})

	// Flow Register
	mux.HandleFunc("POST "+p+"/auth/register", handle(h, http.StatusCreated, "Pendaftaran berhasil.", h.svc.Register))
	// Flow Login (Email)
	mux.HandleFunc("POST "+p+"/auth/login", handle(h, http.StatusOK, "Login berhasil.", h.svc.Login))
	// Flow Login (WhatsApp + OTP)
	mux.HandleFunc("POST "+p+"/auth/login/whatsapp/otp/request", handle(h, http.StatusOK, "Jika nomor terdaftar, kode OTP telah dikirim via WhatsApp.", h.svc.RequestLoginOTP))
	mux.HandleFunc("POST "+p+"/auth/login/whatsapp/otp/verify", handle(h, http.StatusOK, "Login berhasil.", h.svc.VerifyLoginOTP))
	// Flow Lupa Password
	mux.HandleFunc("POST "+p+"/auth/password/forgot", handle(h, http.StatusOK, "Jika akun terdaftar, kode OTP telah dikirim.", h.svc.ForgotPassword))
	mux.HandleFunc("POST "+p+"/auth/password/otp/verify", handle(h, http.StatusOK, "Kode OTP terverifikasi.", h.svc.VerifyResetOTP))
	mux.HandleFunc("POST "+p+"/auth/password/reset", handle(h, http.StatusOK, "Kata sandi berhasil diubah.", h.svc.ResetPassword))
	// Session
	mux.HandleFunc("POST "+p+"/auth/token/refresh", handle(h, http.StatusOK, "Token diperbarui.", h.svc.Refresh))
	mux.HandleFunc("POST "+p+"/auth/logout", h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		var in service.LogoutInput
		if !h.decode(w, r, &in) {
			return
		}
		if err := h.svc.Logout(r.Context(), userID(r), in); err != nil {
			h.fail(w, r, err)
			return
		}
		h.ok(w, http.StatusOK, "Logout berhasil.", nil)
	}))
	mux.HandleFunc("GET "+p+"/users/me", h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		u, err := h.svc.Me(r.Context(), userID(r))
		if err != nil {
			h.fail(w, r, err)
			return
		}
		h.ok(w, http.StatusOK, "", u)
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h.fail(w, r, domain.NewError(http.StatusNotFound, "not_found", "Endpoint tidak ditemukan."))
	})

	var out http.Handler = mux
	out = newLimiter(h.ratePerMin).middleware(h, out)
	out = h.logging(out)
	out = h.recoverer(out)
	return out
}

const swaggerHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Amanah Auth API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head>
<body><div id="ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:'/openapi.yaml',dom_id:'#ui'})</script></body></html>`
