package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"soa/homework-2/internal/api"
)

var (
	ErrTokenExpired = errors.New("token expired")
	ErrTokenInvalid = errors.New("token invalid")
)

const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

type JWTManager struct {
	secret    []byte
	accessTTL time.Duration
}

type AccessClaims struct {
	UserID int64
	Role   api.UserRole
	Exp    int64
}

type RefreshClaims struct {
	UserID int64
	Role   api.UserRole
	Exp    int64
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtPayload struct {
	Sub       string `json:"sub"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
}

func NewJWTManager(secret string, accessTTL time.Duration) *JWTManager {
	return &JWTManager{
		secret:    []byte(secret),
		accessTTL: accessTTL,
	}
}

func (m *JWTManager) GenerateAccessToken(userID int64, role api.UserRole) (string, int64, error) {
	token, expUnix, err := m.generateToken(userID, role, tokenTypeAccess, m.accessTTL)
	if err != nil {
		return "", 0, err
	}
	return token, expUnix - time.Now().UTC().Unix(), nil
}

func (m *JWTManager) GenerateRefreshToken(userID int64, role api.UserRole, ttl time.Duration) (string, time.Time, error) {
	token, expUnix, err := m.generateToken(userID, role, tokenTypeRefresh, ttl)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, time.Unix(expUnix, 0).UTC(), nil
}

func (m *JWTManager) ParseAccessToken(token string) (AccessClaims, error) {
	payload, err := m.parseToken(token, tokenTypeAccess)
	if err != nil {
		return AccessClaims{}, err
	}
	return AccessClaims{UserID: payload.UserID, Role: payload.Role, Exp: payload.Exp}, nil
}

func (m *JWTManager) ParseRefreshToken(token string) (RefreshClaims, error) {
	payload, err := m.parseToken(token, tokenTypeRefresh)
	if err != nil {
		return RefreshClaims{}, err
	}
	return RefreshClaims{UserID: payload.UserID, Role: payload.Role, Exp: payload.Exp}, nil
}

func (m *JWTManager) generateToken(userID int64, role api.UserRole, tokenType string, ttl time.Duration) (string, int64, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl).Unix()

	headerJSON, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", 0, err
	}
	payloadJSON, err := json.Marshal(jwtPayload{
		Sub:       strconv.FormatInt(userID, 10),
		Role:      string(role),
		TokenType: tokenType,
		Exp:       exp,
		Iat:       now.Unix(),
	})
	if err != nil {
		return "", 0, err
	}

	hEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	pEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)
	unsigned := hEnc + "." + pEnc
	signature := m.sign(unsigned)

	return unsigned + "." + signature, exp, nil
}

type parsedClaims struct {
	UserID    int64
	Role      api.UserRole
	Exp       int64
	TokenType string
}

func (m *JWTManager) parseToken(token string, expectedTokenType string) (parsedClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return parsedClaims{}, ErrTokenInvalid
	}

	unsigned := parts[0] + "." + parts[1]
	expected := m.sign(unsigned)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return parsedClaims{}, ErrTokenInvalid
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return parsedClaims{}, ErrTokenInvalid
	}

	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return parsedClaims{}, ErrTokenInvalid
	}

	if payload.TokenType != expectedTokenType {
		return parsedClaims{}, ErrTokenInvalid
	}
	if payload.Exp <= time.Now().UTC().Unix() {
		return parsedClaims{}, ErrTokenExpired
	}

	userID, err := strconv.ParseInt(payload.Sub, 10, 64)
	if err != nil {
		return parsedClaims{}, ErrTokenInvalid
	}
	role := api.UserRole(payload.Role)
	if role != api.USER && role != api.SELLER && role != api.ADMIN {
		return parsedClaims{}, ErrTokenInvalid
	}

	return parsedClaims{UserID: userID, Role: role, Exp: payload.Exp, TokenType: payload.TokenType}, nil
}

func ExtractBearerToken(authHeader string) (string, error) {
	header := strings.TrimSpace(authHeader)
	if header == "" {
		return "", ErrTokenInvalid
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrTokenInvalid
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", ErrTokenInvalid
	}
	return token, nil
}

func (m *JWTManager) sign(unsigned string) string {
	h := hmac.New(sha256.New, m.secret)
	_, _ = h.Write([]byte(unsigned))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func ValidateJWTSecret(secret string) error {
	if len(strings.TrimSpace(secret)) < 16 {
		return fmt.Errorf("JWT secret must be at least 16 characters")
	}
	return nil
}
