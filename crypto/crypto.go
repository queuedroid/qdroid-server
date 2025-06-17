// SPDX-License-Identifier: GPL-3.0-only

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"qdroid-server/commons"

	"golang.org/x/crypto/argon2"
)

const (
	time    = 1
	memory  = 64 * 1024
	threads = 4
	keyLen  = 32
	saltLen = 16
)

func HashPassword(password string) (string, error) {
	commons.Logger.Debug("Hashing password")

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)

	encoded := fmt.Sprintf("$argon2id$v=19$t=%d$m=%d$p=%d$%s$%s",
		time, memory, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	commons.Logger.Debug("Password hashed")
	return encoded, nil
}

func VerifyPassword(password, encodedHash string) error {
	commons.Logger.Debug("Verifying password")

	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return fmt.Errorf("invalid encoded hash format")
	}

	var t, m, p uint32
	_, err := fmt.Sscanf(parts[3], "t=%d", &t)
	_, err2 := fmt.Sscanf(parts[4], "m=%d", &m)
	_, err3 := fmt.Sscanf(parts[5], "p=%d", &p)

	if err != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("failed to parse Argon2 parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("failed to decode hash: %w", err)
	}

	newHash := argon2.IDKey([]byte(password), salt, t, m, threads, uint32(len(hash)))

	if subtleConstantTimeCompare(hash, newHash) {
		return nil
	}

	return fmt.Errorf("password verification failed")
}

func subtleConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
