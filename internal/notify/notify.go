// Package notify mengirim OTP lewat WhatsApp / email.
// Implementasi produksi (WhatsApp Business API, SMTP/SES, dll) cukup memenuhi interface Sender.
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"amanah-auth/internal/domain"
)

type OTPMessage struct {
	Channel domain.OTPChannel
	Target  string
	Code    string
	TTL     time.Duration
}

func (m OTPMessage) Text() string {
	return fmt.Sprintf("Kode OTP Amanah Anda: %s. Berlaku %d menit. Jangan bagikan kode ini ke siapapun, termasuk pihak Amanah.",
		m.Code, int(m.TTL.Minutes()))
}

type Sender interface {
	Send(ctx context.Context, msg OTPMessage) error
}

// LogSender: pengganti provider saat development. Kode OTP hanya ditulis bila ShowCode=true.
type LogSender struct {
	Log      *slog.Logger
	ShowCode bool
}

func (s LogSender) Send(_ context.Context, m OTPMessage) error {
	if s.ShowCode {
		s.Log.Info("OTP terkirim (DEV)", "channel", m.Channel, "target", m.Target, "code", m.Code)
	} else {
		s.Log.Info("OTP terkirim", "channel", m.Channel, "target", m.Target)
	}
	return nil
}

// Recorder menyimpan pesan di memori (untuk test).
type Recorder struct {
	mu   sync.Mutex
	Msgs []OTPMessage
	Fail bool
}

func (r *Recorder) Send(_ context.Context, m OTPMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Fail {
		return fmt.Errorf("provider down")
	}
	r.Msgs = append(r.Msgs, m)
	return nil
}

func (r *Recorder) Last() (OTPMessage, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.Msgs) == 0 {
		return OTPMessage{}, false
	}
	return r.Msgs[len(r.Msgs)-1], true
}

func (r *Recorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Msgs)
}
