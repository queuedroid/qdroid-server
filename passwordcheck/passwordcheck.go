package passwordcheck

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"qdroid-server/commons"
	"strings"
	"unicode"
)

func ValidatePassword(ctx context.Context, password string) error {
	if len([]rune(password)) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	if !hasUppercase(password) {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLowercase(password) {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasDigit(password) {
		return errors.New("password must contain at least one digit")
	}
	if !hasSpecialChar(password) {
		return errors.New("password must contain at least one special character (e.g., !@#$%)")
	}

	if commons.GetEnv("PWNED_PASSWORDS_ENABLED", "true") == "true" {
		pwned, err := checkPasswordPwned(ctx, password)
		if err != nil {
			commons.Logger.Error("Error checking pwned passwords:", err)
		}
		if pwned {
			return errors.New("password has been found in data breaches (pwned); choose a different one")
		}
	}

	return nil
}

func checkPasswordPwned(ctx context.Context, password string) (bool, error) {
	hasher := sha1.New()
	hasher.Write([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))

	prefix, suffix := hash[:5], hash[5:]
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("HIBP API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read HIBP response: %w", err)
	}

	for _, line := range strings.Split(string(body), "\n") {
		if parts := strings.Split(line, ":"); len(parts) == 2 {
			if strings.TrimSpace(parts[0]) == suffix {
				return true, nil
			}
		}
	}
	return false, nil
}

func hasUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func hasLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func hasDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func hasSpecialChar(s string) bool {
	for _, r := range s {
		if unicode.IsSymbol(r) || unicode.IsPunct(r) {
			return true
		}
	}
	return false
}
