package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type contextKey string

const (
	requestIDHeader = "X-Request-Id"
	requestIDKey    = contextKey("request_id")
	userIDKey       = contextKey("user_id")
	userRoleKey     = contextKey("user_role")
)

type logEntry struct {
	RequestID   string      `json:"request_id"`
	Method      string      `json:"method"`
	Endpoint    string      `json:"endpoint"`
	StatusCode  int         `json:"status_code"`
	DurationMS  int64       `json:"duration_ms"`
	UserID      interface{} `json:"user_id"`
	Timestamp   string      `json:"timestamp"`
	RequestBody interface{} `json:"request_body"`
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(data)
}

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := newRequestID()
		w.Header().Set(requestIDHeader, requestID)
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func LoggingMiddleware(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now().UTC()
			recorder := &statusRecorder{ResponseWriter: w}

			var requestBody interface{}
			if methodHasBody(r.Method) {
				body, restoredBody := readAndRestoreBody(r.Body)
				r.Body = restoredBody
				requestBody = sanitizeBody(body)
			}

			next.ServeHTTP(recorder, r)
			if recorder.status == 0 {
				recorder.status = http.StatusOK
			}

			entry := logEntry{
				RequestID:   RequestIDFromContext(r.Context()),
				Method:      r.Method,
				Endpoint:    r.URL.Path,
				StatusCode:  recorder.status,
				DurationMS:  time.Since(start).Milliseconds(),
				UserID:      userIDLogValue(r.Context()),
				Timestamp:   start.Format(time.RFC3339Nano),
				RequestBody: requestBody,
			}

			payload, err := json.Marshal(entry)
			if err != nil {
				logger.Printf("{\"message\":\"failed to marshal log entry\",\"error\":%q}", err.Error())
				return
			}
			logger.Println(string(payload))
		})
	}
}

func RequestIDFromContext(ctx context.Context) string {
	value, ok := ctx.Value(requestIDKey).(string)
	if !ok {
		return ""
	}
	return value
}

func withAuthContext(ctx context.Context, userID int64, role string) context.Context {
	ctx = context.WithValue(ctx, userIDKey, userID)
	ctx = context.WithValue(ctx, userRoleKey, role)
	return ctx
}

func UserIDFromContext(ctx context.Context) (int64, bool) {
	value, ok := ctx.Value(userIDKey).(int64)
	return value, ok
}

func userIDLogValue(ctx context.Context) interface{} {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return nil
	}
	return userID
}

func methodHasBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func readAndRestoreBody(body io.ReadCloser) ([]byte, io.ReadCloser) {
	if body == nil {
		return nil, io.NopCloser(bytes.NewReader(nil))
	}

	defer body.Close()
	content, err := io.ReadAll(body)
	if err != nil {
		return nil, io.NopCloser(bytes.NewReader(nil))
	}
	return content, io.NopCloser(bytes.NewReader(content))
}

func sanitizeBody(body []byte) interface{} {
	if len(body) == 0 {
		return nil
	}

	var payload interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		text := string(body)
		if len(text) > 2000 {
			return text[:2000] + "...truncated"
		}
		return text
	}

	maskSensitive(payload)
	return payload
}

func maskSensitive(value interface{}) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, nested := range typed {
			if isSensitiveKey(key) {
				typed[key] = "***"
				continue
			}
			maskSensitive(nested)
		}
	case []interface{}:
		for _, item := range typed {
			maskSensitive(item)
		}
	}
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	switch normalized {
	case "password", "passwd", "token", "access_token", "refresh_token", "secret":
		return true
	default:
		return false
	}
}

func newRequestID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}

	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}
