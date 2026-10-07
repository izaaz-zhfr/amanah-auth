package service

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	nameRe  = regexp.MustCompile(`^\p{L}[\p{L}\s.'-]{1,99}$`)
	phoneRe = regexp.MustCompile(`^\+628\d{8,11}$`)
	codeRe  = regexp.MustCompile(`^\d{6}$`)
)

func normalizeEmail(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 254 {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s {
		return "", false
	}
	at := strings.LastIndex(s, "@")
	if !strings.Contains(s[at+1:], ".") {
		return "", false
	}
	return s, true
}

// normalizePhone: terima +62812..., 0812..., 62812..., 812... (spasi/strip diabaikan) -> +62812...
func normalizePhone(s string) (string, bool) {
	r := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "")
	s = r.Replace(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(s, "+62"):
	case strings.HasPrefix(s, "62"):
		s = "+" + s
	case strings.HasPrefix(s, "0"):
		s = "+62" + s[1:]
	case strings.HasPrefix(s, "8"):
		s = "+62" + s
	default:
		return "", false
	}
	if !phoneRe.MatchString(s) {
		return "", false
	}
	return s, true
}

func validName(s string) bool { return nameRe.MatchString(s) }

func validCode(s string) bool { return codeRe.MatchString(s) }

// passwordProblems mengembalikan daftar aturan yang dilanggar (kosong = valid).
func passwordProblems(pw string) []string {
	var p []string
	if utf8.RuneCountInString(pw) < 8 {
		p = append(p, "Minimal 8 karakter")
	}
	if len(pw) > 72 {
		p = append(p, "Maksimal 72 byte")
	}
	var up, lo, di, sy bool
	for _, c := range pw {
		switch {
		case unicode.IsUpper(c):
			up = true
		case unicode.IsLower(c):
			lo = true
		case unicode.IsDigit(c):
			di = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			sy = true
		}
	}
	if !up || !lo {
		p = append(p, "Kombinasi huruf besar & kecil")
	}
	if !di {
		p = append(p, "Mengandung angka (0-9)")
	}
	if !sy {
		p = append(p, "Mengandung simbol atau karakter khusus (@#$%)")
	}
	return p
}

func maskEmail(e string) string {
	at := strings.LastIndex(e, "@")
	if at < 1 {
		return "***"
	}
	n := 3
	if at < n {
		n = at
	}
	return e[:n] + "***" + e[at:]
}

func maskPhone(p string) string {
	if len(p) < 8 {
		return "***"
	}
	return p[:3] + " " + p[3:6] + "-****-" + p[len(p)-4:]
}
