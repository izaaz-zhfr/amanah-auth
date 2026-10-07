package handler

import (
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"amanah-auth/internal/domain"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }

func (h *Handler) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		h.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"ms", time.Since(start).Milliseconds(), "ip", clientIP(r))
	})
}

func (h *Handler) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				h.log.Error("panic", "err", rec, "stack", string(debug.Stack()))
				h.fail(w, r, domain.ErrInternal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// limiter: fixed-window per IP, hanya untuk /api/v1/auth/*.
// Untuk deployment multi-instance gunakan Redis / API gateway.
type limiter struct {
	mu    sync.Mutex
	limit int
	hits  map[string]*window
}

type window struct {
	start time.Time
	n     int
}

func newLimiter(limit int) *limiter { return &limiter{limit: limit, hits: map[string]*window{}} }

func (l *limiter) allow(key string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.hits) > 10000 {
		for k, w := range l.hits {
			if now.Sub(w.start) > time.Minute {
				delete(l.hits, k)
			}
		}
	}
	w, ok := l.hits[key]
	if !ok || now.Sub(w.start) >= time.Minute {
		l.hits[key] = &window{start: now, n: 1}
		return true, 0
	}
	if w.n >= l.limit {
		return false, int(time.Minute.Seconds()-now.Sub(w.start).Seconds()) + 1
	}
	w.n++
	return true, 0
}

func (l *limiter) middleware(h *Handler, next http.Handler) http.Handler {
	if l.limit <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
			if ok, retry := l.allow(clientIP(r), time.Now()); !ok {
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				h.fail(w, r, domain.ErrTooManyRequests.With("retry_after_seconds", retry))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
