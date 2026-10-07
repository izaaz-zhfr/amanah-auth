# Amanah Auth API (Golang + PostgreSQL)

REST API untuk 4 flow di Figma "Autentikasi Test": **Login Email**, **Login WhatsApp + OTP**, **Register**, **Lupa Password + OTP**.

## Menjalankan

### Lokal (Go + PostgreSQL)
```bash
createdb amanah
psql amanah -f migrations/001_init.sql
cp .env.example .env            # isi JWT_SECRET, OTP_SECRET, DATABASE_URL
go mod tidy
go run ./cmd/api
```
Linux/Mac: muat `.env` dengan `set -a; source .env; set +a`. Windows PowerShell: set `$env:DATABASE_URL`, `$env:JWT_SECRET`, `$env:OTP_SECRET`, `$env:LOG_OTP="true"` lalu `go run ./cmd/api`.
Swagger UI: http://localhost:8080/docs. Kode OTP muncul di log server (`LOG_OTP=true`, khusus dev).
Tanpa database (demo saja): `STORE_DRIVER=memory`.

## Test
```bash
go test ./... -race                      # memakai in-memory store
make test-pg                             # PostgreSQL (ubah USER:PASS di Makefile)
```

## Layar Figma -> Endpoint

| Flow / layar | Endpoint |
|---|---|
| Register | `POST /api/v1/auth/register` |
| Login Email (+ "Sisa 2x", akun beku) | `POST /api/v1/auth/login` |
| Login WA - Kirim Kode OTP / Kirim Ulang | `POST /api/v1/auth/login/whatsapp/otp/request` |
| Login WA - Coba Verifikasi Lagi | `POST /api/v1/auth/login/whatsapp/otp/verify` |
| Lupa Password - Kirim Kode OTP | `POST /api/v1/auth/password/forgot` |
| Lupa Password - Verifikasi & Buat Sandi Baru | `POST /api/v1/auth/password/otp/verify` |
| Lupa Password - Simpan Kata Sandi & Masuk | `POST /api/v1/auth/password/reset` |
| Beranda (butuh login) | `GET /api/v1/users/me` |
| Refresh / Logout | `POST /api/v1/auth/token/refresh`, `POST /api/v1/auth/logout` |

Detail request/response: `docs/openapi.yaml` (Swagger di `/docs`) dan `postman/Amanah-Auth.postman_collection.json`.
Dokumen database (ERD, tabel, relasi, constraint, index): `docs/DATABASE.md`.

## Aturan bisnis

| Aturan | Nilai |
|---|---|
| Password | min 8, huruf besar+kecil, angka, simbol, maks 72 byte; disimpan bcrypt |
| Password baru (reset) | tidak boleh sama dengan 3 password terakhir |
| Login gagal | maks 5x, lalu akun dibekukan 15 menit (HTTP 423); respons memuat `attempts_remaining` |
| OTP | 6 digit, berlaku 5 menit, sekali pakai, maks 5x salah (lalu hangus + akun beku 15 menit untuk login WA) |
| Kirim ulang OTP | cooldown 60 detik (HTTP 429 + `Retry-After`) |
| Access token | JWT HS256, 15 menit |
| Refresh token | acak 256-bit, disimpan hash-nya, dirotasi tiap pakai, pakai ulang token lama = semua sesi dicabut. 24 jam, atau 30 hari bila `remember_me` |
| Anti user-enumeration | request OTP untuk akun yang tidak ada tetap 200 |
| Rate limit | 60 req/menit per IP pada `/api/v1/auth/*` |

## Format error

```json
{ "success": false,
  "error": { "code": "invalid_credentials", "message": "...", "details": {"field": "..."}, "meta": {"attempts_remaining": 2} } }
```

| Status | Kapan |
|---|---|
| 200 / 201 | sukses / register sukses |
| 400 | JSON rusak, OTP salah/kedaluwarsa, reset token tidak valid |
| 401 | kredensial salah, token tidak valid |
| 409 | email / WA sudah terdaftar |
| 422 | validasi field gagal, password dipakai ulang |
| 423 | akun dibekukan sementara |
| 429 | rate limit / cooldown OTP |
| 502 | gagal mengirim OTP |

## Catatan
- Pengirim OTP (`internal/notify`) saat ini hanya menulis log. Untuk production, implementasikan interface `notify.Sender` dengan WhatsApp Business API dan SMTP/SES.
- Layar "Email atau Username": Register di Figma tidak punya field username, jadi login memakai email.
- Rate limiter in-memory; untuk multi-instance pindahkan ke Redis / API gateway.
