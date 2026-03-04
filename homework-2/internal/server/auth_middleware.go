package server

import (
	"errors"
	"net/http"
	"strings"

	"soa/homework-2/internal/auth"
)

func AuthMiddleware(jwtManager *auth.JWTManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublicEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			token, err := auth.ExtractBearerToken(r.Header.Get("Authorization"))
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, tokenInvalidError())
				return
			}

			claims, err := jwtManager.ParseAccessToken(token)
			if err != nil {
				if errors.Is(err, auth.ErrTokenExpired) {
					writeJSONError(w, http.StatusUnauthorized, tokenExpiredError())
					return
				}
				writeJSONError(w, http.StatusUnauthorized, tokenInvalidError())
				return
			}

			ctx := withAuthContext(r.Context(), claims.UserID, string(claims.Role))
			*r = *r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func isPublicEndpoint(path string) bool {
	if path == "/health" {
		return true
	}
	return strings.HasPrefix(path, "/auth/")
}
