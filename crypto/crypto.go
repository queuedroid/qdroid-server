// SPDX-License-Identifier: GPL-3.0-only

package crypto

import (
	"encoding/base64"
	"qdroid-server/commons"
	"strings"

	"golang.org/x/crypto/argon2"
)

func HashPassword(password string) string {
	commons.Logger.Debug("Hashing password")
	salt := []byte("somesalt") // For demo only. Use a random salt per user in production!
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	commons.Logger.Debug("Password hashed")
	return b64Hash
}

func VerifyPassword(password, hash string) bool {
	commons.Logger.Debug("Verifying password")
	salt := []byte("somesalt") // Use the same salt as in HashPassword
	newHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	b64NewHash := base64.RawStdEncoding.EncodeToString(newHash)
	result := strings.Compare(b64NewHash, hash) == 0
	if result {
		commons.Logger.Debug("Password verification succeeded")
	} else {
		commons.Logger.Error("Password verification failed")
	}
	return result
}
