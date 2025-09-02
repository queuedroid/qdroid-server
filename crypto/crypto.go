// SPDX-License-Identifier: GPL-3.0-only

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"qdroid-server/commons"
	"strconv"

	"github.com/alexedwards/argon2id"
)

func NewCrypto() *Crypto {
	var (
		argonTime     uint32
		argonMemory   uint32
		argonThreads  uint8
		argonKeyLen   uint32
		argonSaltLen  uint32
		encryptionKey string
		hashingPepper string
	)
	if v := commons.GetEnv("ARGON2_TIME", "1"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			argonTime = uint32(i)
		}
	}
	if v := commons.GetEnv("ARGON2_MEMORY", "65536"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			argonMemory = uint32(i)
		}
	}
	if v := commons.GetEnv("ARGON2_THREADS", "2"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			argonThreads = uint8(i)
		}
	}
	if v := commons.GetEnv("ARGON2_KEYLEN", "32"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			argonKeyLen = uint32(i)
		}
	}
	if v := commons.GetEnv("ARGON2_SALTLEN", "16"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			argonSaltLen = uint32(i)
		}
	}

	encryptionKey = commons.GetEnv("ENCRYPTION_KEY", "12345678901234567890123456789012")
	hashingPepper = commons.GetEnv("HASHING_PEPPER", "12345678901234567890123456789012")

	return &Crypto{
		ArgonTime:     argonTime,
		ArgonMemory:   argonMemory,
		ArgonThreads:  argonThreads,
		ArgonKeyLen:   argonKeyLen,
		ArgonSaltLen:  argonSaltLen,
		EncryptionKey: encryptionKey,
		HashingPepper: hashingPepper,
	}
}

func (c *Crypto) HashPassword(password string) (string, error) {
	commons.Logger.Debug("Hashing password")
	params := &argon2id.Params{
		Memory:      c.ArgonMemory,
		Iterations:  c.ArgonTime,
		Parallelism: c.ArgonThreads,
		SaltLength:  c.ArgonSaltLen,
		KeyLength:   c.ArgonKeyLen,
	}
	hash, err := argon2id.CreateHash(password, params)
	if err != nil {
		return "", err
	}
	commons.Logger.Debug("Password hashed")
	return hash, nil
}

func (c *Crypto) VerifyPassword(password, encodedHash string) error {
	commons.Logger.Debug("Verifying password")
	match, err := argon2id.ComparePasswordAndHash(password, encodedHash)
	if err != nil {
		return err
	}
	if !match {
		return fmt.Errorf("password verification failed")
	}
	return nil
}

func GenerateRandomString(prefix string, length int, encoding string) (string, error) {
	supported_encodings := []string{"hex", "base64"}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	switch encoding {
	case "hex":
		return prefix + hex.EncodeToString(b), nil
	case "base64":
		return prefix + base64.StdEncoding.EncodeToString(b), nil
	default:
		return "", fmt.Errorf("unsupported encoding: %s, Supported encodings are: %s", encoding, supported_encodings)
	}
}

func (c *Crypto) EncryptData(data []byte, algo string) ([]byte, error) {
	commons.Logger.Debug("Encrypting data with algorithm: " + algo)

	switch algo {
	case "AES-GCM":
		return c.encryptAESGCM(data, []byte(c.EncryptionKey))
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algo)
	}
}

func (c *Crypto) DecryptData(encryptedData []byte, algo string) ([]byte, error) {
	commons.Logger.Debug("Decrypting data with algorithm: " + algo)

	switch algo {
	case "AES-GCM":
		return c.decryptAESGCM(encryptedData, []byte(c.EncryptionKey))
	default:
		return nil, fmt.Errorf("unsupported decryption algorithm: %s", algo)
	}
}

func (c *Crypto) HashData(data []byte, algo string) ([]byte, error) {
	commons.Logger.Debug("Hashing data with algorithm: " + algo)

	switch algo {
	case "HMAC-SHA-256":
		return c.hmacSHA256(data, []byte(c.HashingPepper)), nil
	default:
		return nil, fmt.Errorf("unsupported hashing algorithm: %s", algo)
	}
}

func (c *Crypto) VerifyHash(data []byte, expectedHash []byte, algo string) (bool, error) {
	commons.Logger.Debug("Verifying hash with algorithm: " + algo)

	switch algo {
	case "HMAC-SHA-256":
		computedHash := c.hmacSHA256(data, []byte(c.HashingPepper))
		return hmac.Equal(expectedHash, computedHash), nil
	default:
		return false, fmt.Errorf("unsupported hashing algorithm: %s", algo)
	}
}

func (c *Crypto) encryptAESGCM(data []byte, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d bytes. Must be 16, 24, or 32 bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	commons.Logger.Debug("Data encrypted successfully with AES-GCM")
	return ciphertext, nil
}

func (c *Crypto) decryptAESGCM(encryptedData []byte, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d bytes. Must be 16, 24, or 32 bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	commons.Logger.Debug("Data decrypted successfully with AES-GCM")
	return plaintext, nil
}

func (c *Crypto) hmacSHA256(data []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
