// SPDX-License-Identifier: GPL-3.0-only

package crypto

import (
	"bytes"
	"testing"
)

func TestHashPassword(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "12345678901234567890123456789012")
	t.Setenv("HASHING_PEPPER", "test-pepper-for-hashing-operations")
	crypto := NewCrypto()
	password := "testpassword123"

	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if hash == "" {
		t.Error("Hash should not be empty")
	}

	hash2, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("Second HashPassword failed: %v", err)
	}

	if hash == hash2 {
		t.Error("Two hashes of same password should be different (due to salt)")
	}
}

func TestVerifyPassword(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "12345678901234567890123456789012")
	t.Setenv("HASHING_PEPPER", "test-pepper-for-hashing-operations")
	crypto := NewCrypto()
	password := "testpassword123"
	wrongPassword := "wrongpassword"

	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	err = crypto.VerifyPassword(password, hash)
	if err != nil {
		t.Errorf("VerifyPassword failed for correct password: %v", err)
	}

	err = crypto.VerifyPassword(wrongPassword, hash)
	if err == nil {
		t.Error("VerifyPassword should fail for wrong password")
	}

	err = crypto.VerifyPassword(password, "invalid-hash")
	if err == nil {
		t.Error("VerifyPassword should fail for invalid hash")
	}
}

func TestEncryptDecryptData(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "12345678901234567890123456789012")
	t.Setenv("HASHING_PEPPER", "test-pepper-for-hashing-operations")
	crypto := NewCrypto()
	testData := []byte("This is test data to encrypt")

	encrypted, err := crypto.EncryptData(testData, "AES-GCM")
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	if bytes.Equal(encrypted, testData) {
		t.Error("Encrypted data should be different from original")
	}

	decrypted, err := crypto.DecryptData(encrypted, "AES-GCM")
	if err != nil {
		t.Fatalf("DecryptData failed: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Error("Decrypted data should match original data")
	}

	_, err = crypto.EncryptData(testData, "UNSUPPORTED")
	if err == nil {
		t.Error("EncryptData should fail for unsupported algorithm")
	}

	_, err = crypto.DecryptData(encrypted, "UNSUPPORTED")
	if err == nil {
		t.Error("DecryptData should fail for unsupported algorithm")
	}
}

func TestHashData(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "12345678901234567890123456789012")
	t.Setenv("HASHING_PEPPER", "test-pepper-for-hashing-operations")
	crypto := NewCrypto()
	testData := []byte("test data for hashing")

	hash, err := crypto.HashData(testData, "HMAC-SHA-256")
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}

	if len(hash) != 32 {
		t.Errorf("Expected hash length 32, got %d", len(hash))
	}

	hash2, err := crypto.HashData(testData, "HMAC-SHA-256")
	if err != nil {
		t.Fatalf("Second HashData failed: %v", err)
	}

	if !bytes.Equal(hash, hash2) {
		t.Error("Same data should produce same hash")
	}

	differentData := []byte("different test data")
	hash3, err := crypto.HashData(differentData, "HMAC-SHA-256")
	if err != nil {
		t.Fatalf("HashData with different data failed: %v", err)
	}

	if bytes.Equal(hash, hash3) {
		t.Error("Different data should produce different hash")
	}

	_, err = crypto.HashData(testData, "UNSUPPORTED")
	if err == nil {
		t.Error("HashData should fail for unsupported algorithm")
	}
}

func TestVerifyHash(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "12345678901234567890123456789012")
	t.Setenv("HASHING_PEPPER", "test-pepper-for-hashing-operations")
	crypto := NewCrypto()
	testData := []byte("test data for hash verification")

	hash, err := crypto.HashData(testData, "HMAC-SHA-256")
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}

	valid, err := crypto.VerifyHash(testData, hash, "HMAC-SHA-256")
	if err != nil {
		t.Fatalf("VerifyHash failed: %v", err)
	}

	if !valid {
		t.Error("Hash verification should succeed for correct hash")
	}

	wrongHash := []byte("wrong hash")
	valid, err = crypto.VerifyHash(testData, wrongHash, "HMAC-SHA-256")
	if err != nil {
		t.Fatalf("VerifyHash with wrong hash failed: %v", err)
	}

	if valid {
		t.Error("Hash verification should fail for wrong hash")
	}

	_, err = crypto.VerifyHash(testData, hash, "UNSUPPORTED")
	if err == nil {
		t.Error("VerifyHash should fail for unsupported algorithm")
	}
}

func TestEncryptDecryptEdgeCases(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "12345678901234567890123456789012")
	t.Setenv("HASHING_PEPPER", "test-pepper-for-hashing-operations")
	crypto := NewCrypto()

	empty := []byte{}
	encrypted, err := crypto.EncryptData(empty, "AES-GCM")
	if err != nil {
		t.Fatalf("EncryptData with empty data failed: %v", err)
	}

	decrypted, err := crypto.DecryptData(encrypted, "AES-GCM")
	if err != nil {
		t.Fatalf("DecryptData with empty data failed: %v", err)
	}

	if !bytes.Equal(decrypted, empty) {
		t.Error("Decrypted empty data should equal original empty data")
	}

	_, err = crypto.DecryptData([]byte("invalid"), "AES-GCM")
	if err == nil {
		t.Error("DecryptData should fail with invalid encrypted data")
	}
}

func TestInvalidKeyLengths(t *testing.T) {
	crypto := &Crypto{
		EncryptionKey: "short",
		HashingPepper: "pepper",
	}

	testData := []byte("test")
	_, err := crypto.EncryptData(testData, "AES-GCM")
	if err == nil {
		t.Error("EncryptData should fail with invalid key length")
	}

	_, err = crypto.DecryptData(testData, "AES-GCM")
	if err == nil {
		t.Error("DecryptData should fail with invalid key length")
	}
}
