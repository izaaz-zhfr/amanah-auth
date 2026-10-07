package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"amanah-auth/internal/config"
	"amanah-auth/internal/handler"
	"amanah-auth/internal/notify"
	"amanah-auth/internal/service"
	"amanah-auth/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		log.Error("config tidak valid", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var st store.Store
	switch cfg.StoreDriver {
	case "memory":
		log.Warn("memakai in-memory store: data hilang saat restart (hanya untuk demo)")
		st = store.NewMemory()
	default:
		pg, err := store.NewPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			log.Error("gagal konek database", "err", err)
			os.Exit(1)
		}
		defer pg.Close()
		st = pg
	}

	// Ganti LogSender dengan provider WhatsApp / email sungguhan di production.
	sender := notify.LogSender{Log: log, ShowCode: cfg.LogOTP}
	svc := service.New(cfg, st, sender, log)

	go func() { // bersihkan data kedaluwarsa tiap jam
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := svc.Cleanup(ctx); err != nil {
					log.Error("cleanup gagal", "err", err)
				}
			}
		}
	}()

	srv := &http.Server{
		Addr: ":" + cfg.Port, Handler: handler.New(svc, log, cfg.RateLimitPerMin).Routes(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	go func() {
		log.Info("server berjalan", "addr", srv.Addr, "env", cfg.Env, "store", cfg.StoreDriver)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	log.Info("server berhenti")
}
