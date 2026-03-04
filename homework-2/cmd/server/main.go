package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"

	"soa/homework-2/internal/api"
	"soa/homework-2/internal/auth"
	"soa/homework-2/internal/server"
	"soa/homework-2/internal/store"
)

func main() {
	log.SetFlags(0)

	addr := env("HTTP_ADDR", ":8080")
	dsn := env("DB_DSN", "postgres://marketplace:marketplace@localhost:5432/marketplace?sslmode=disable")
	jwtSecret := env("JWT_SECRET", "change-me-please-very-secret")
	accessTTL := envDurationMinutes("ACCESS_TOKEN_MINUTES", 20)
	refreshTTL := envDurationDays("REFRESH_TOKEN_DAYS", 14)

	if err := auth.ValidateJWTSecret(jwtSecret); err != nil {
		log.Fatalf("jwt secret: %v", err)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("ping db: %v", err)
	}

	productStore := store.NewProductStore(db)
	authStore := store.NewAuthStore(db)
	jwtManager := auth.NewJWTManager(jwtSecret, accessTTL)
	openapiValidationMiddleware, err := server.NewOpenAPIValidationMiddleware()
	if err != nil {
		log.Fatalf("openapi validator: %v", err)
	}

	strict := api.NewStrictHandlerWithOptions(server.New(productStore, authStore, jwtManager, refreshTTL), nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  server.RequestErrorHandler,
		ResponseErrorHandlerFunc: server.ResponseErrorHandler,
	})

	r := chi.NewRouter()
	r.Use(server.RequestIDMiddleware)
	r.Use(server.LoggingMiddleware(log.Default()))
	r.Use(server.AuthMiddleware(jwtManager))
	r.Use(openapiValidationMiddleware)
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	api.HandlerFromMux(strict, r)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("server started at %s", addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

func env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func envDurationMinutes(key string, fallback int) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return time.Duration(fallback) * time.Minute
	}
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		log.Fatalf("invalid %s value: %q", key, value)
	}
	return time.Duration(n) * time.Minute
}

func envDurationDays(key string, fallback int) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return time.Duration(fallback) * 24 * time.Hour
	}
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		log.Fatalf("invalid %s value: %q", key, value)
	}
	return time.Duration(n) * 24 * time.Hour
}
