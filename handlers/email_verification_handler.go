// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"errors"
	"net/http"
	"qdroid-server/commons"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/middlewares"
	"qdroid-server/models"
	"qdroid-server/notifications"
	"time"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// SendVerificationEmailHandler godoc
// @Summary      Send verification email
// @Description  Sends a verification email to the user's registered email address
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Success      200 {object} GenericResponse "Verification email sent successfully"
// @Failure      400 {object} echo.HTTPError  "Bad request"
// @Failure      401 {object} echo.HTTPError  "Unauthorized"
// @Failure      409 {object} echo.HTTPError  "Email already verified"
// @Failure      500 {object} echo.HTTPError  "Internal server error"
// @Router       /v1/auth/send-verification-email [post]
func SendVerificationEmailHandler(c echo.Context) error {
	logger := c.Logger()

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	if user.IsEmailVerified {
		logger.Info("User email is already verified")
		return &echo.HTTPError{
			Code:    http.StatusConflict,
			Message: "Email is already verified",
		}
	}

	token, err := crypto.GenerateRandomString("evt_", 32, "hex")
	if err != nil {
		logger.Errorf("Failed to generate verification token: %v", err)
		return echo.ErrInternalServerError
	}

	expiresAt := time.Now().Add(24 * time.Hour)

	emailVerification := models.EmailVerification{}
	if err := db.Conn.Where("user_id = ? AND is_used = ?", user.ID, false).
		Assign(models.EmailVerification{
			Token:     token,
			ExpiresAt: expiresAt,
		}).FirstOrCreate(&emailVerification).Error; err != nil {
		logger.Errorf("Failed to check existing verification tokens: %v", err)
		return echo.ErrInternalServerError
	}

	newCrypto := crypto.NewCrypto()
	emailBytes, err := newCrypto.DecryptData(user.EmailEncrypted, "AES-GCM")
	if err != nil {
		logger.Errorf("Failed to decrypt user email: %v", err)
		return echo.ErrInternalServerError
	}
	email := string(emailBytes)
	fullName := ""

	baseUrl := commons.GetEnv("BASE_URL", "https://api.queuedroid.com")
	verifyLink := commons.GetEnv("EMAIL_VERIFICATION_URL", "https://queuedroid.com") + "/verify-email?token=" + token
	vars := map[string]any{
		"username":          email,
		"product_name":      "Queuedroid",
		"verification_link": verifyLink,
		"base_url":          baseUrl,
		"expiration_hours":  "24",
	}

	if user.FullNameEncrypted != nil && len(*user.FullNameEncrypted) > 0 {
		fullNameBytes, err := newCrypto.DecryptData(*user.FullNameEncrypted, "AES-GCM")
		if err == nil && len(fullNameBytes) > 0 {
			fullName = string(fullNameBytes)
			vars["name"] = fullName
		}
	}

	go notifications.DispatchNotification(notifications.Email, notifications.SMTP, notifications.NotificationData{
		To:        email,
		ToName:    &fullName,
		Subject:   "QueueDroid Account Email Verification",
		Template:  "verification",
		Variables: vars,
	})

	logger.Infof("Verification email sent successfully.")
	return c.JSON(http.StatusOK, GenericResponse{
		Message: "Verification email sent successfully",
	})
}

// VerifyEmailHandler godoc
// @Summary      Verify email address
// @Description  Verifies the user's email address using the token sent via email
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        verifyEmailRequest  body  VerifyEmailRequest  true  "Email verification request"
// @Success      200 {object} GenericResponse "Email verified successfully"
// @Failure      400 {object} echo.HTTPError  "Bad request or invalid token"
// @Failure      410 {object} echo.HTTPError  "Token expired"
// @Failure      500 {object} echo.HTTPError  "Internal server error"
// @Router       /v1/auth/verify-email [post]
func VerifyEmailHandler(c echo.Context) error {
	logger := c.Logger()

	var req VerifyEmailRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid verification request payload:", err)
		return echo.ErrBadRequest
	}

	if req.Token == "" {
		logger.Error("Verification token is required")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "token field is required",
		}
	}

	verification := models.EmailVerification{}

	if err := db.Conn.Preload("User").
		Where("token = ? AND is_used = ?", req.Token, false).
		First(&verification).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("Invalid or already used verification token")
			return &echo.HTTPError{
				Code:    http.StatusBadRequest,
				Message: "Invalid or already used verification token",
			}
		}
		logger.Errorf("Failed to find verification record: %v", err)
		return echo.ErrInternalServerError
	}

	if time.Now().After(verification.ExpiresAt) {
		logger.Error("Verification token has expired")
		return &echo.HTTPError{
			Code:    http.StatusGone,
			Message: "Verification token has expired. Please request a new one.",
		}
	}

	tx := db.Conn.Begin()
	if tx.Error != nil {
		logger.Errorf("Transaction begin failed: %v", tx.Error)
		return echo.ErrInternalServerError
	}

	verification.IsUsed = true
	if err := tx.Save(&verification).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to mark token as used: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Model(&verification.User).
		Update("is_email_verified", true).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to update user verification status: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		logger.Errorf("Transaction commit failed: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("Email verified successfully for user %d", verification.UserID)
	return c.JSON(http.StatusOK, GenericResponse{
		Message: "Email verified successfully",
	})
}

// ResendVerificationEmailHandler godoc
// @Summary      Resend verification email
// @Description  Resends verification email (rate limited)
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Success      200 {object} GenericResponse "Verification email resent successfully"
// @Failure      400 {object} echo.HTTPError  "Bad request"
// @Failure      401 {object} echo.HTTPError  "Unauthorized"
// @Failure      409 {object} echo.HTTPError  "Email already verified"
// @Failure      429 {object} echo.HTTPError  "Too many requests"
// @Failure      500 {object} echo.HTTPError  "Internal server error"
// @Router       /v1/auth/resend-verification-email [post]
func ResendVerificationEmailHandler(c echo.Context) error {
	logger := c.Logger()

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	if user.IsEmailVerified {
		logger.Info("User email is already verified")
		return &echo.HTTPError{
			Code:    http.StatusConflict,
			Message: "Email is already verified",
		}
	}

	recentVerification := models.EmailVerification{}

	if err := db.Conn.Where("user_id = ? AND created_at > ?", user.ID, time.Now().Add(-5*time.Minute)).
		First(&recentVerification).Error; err == nil {
		logger.Info("Recent verification email already sent")
		return &echo.HTTPError{
			Code:    http.StatusTooManyRequests,
			Message: "Please wait 5 minutes before requesting another verification email",
		}
	}

	return SendVerificationEmailHandler(c)
}
