package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := sha256.Sum256(append(salt, []byte(password)...))
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash[:]), nil
}

func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, ":")
	if len(parts) != 2 {
		return false
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	storedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}

	calculated := sha256.Sum256(append(salt, []byte(password)...))
	if len(storedHash) != len(calculated) {
		return false
	}

	return subtle.ConstantTimeCompare(storedHash, calculated[:]) == 1
}
