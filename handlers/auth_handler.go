// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"qdroid-server/commons"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/middlewares"
	"qdroid-server/models"
	"qdroid-server/notifications"
	"qdroid-server/passwordcheck"
	"qdroid-server/rabbitmq"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/nyaruka/phonenumbers"
	"gorm.io/gorm"
)

func generateSessionToken(c echo.Context, user models.User, newCrypto crypto.Crypto) (string, error) {
	logger := c.Logger()

	sessionToken, err := crypto.GenerateRandomString("st_long_", 32, "hex")
	if err != nil {
		logger.Errorf("Failed to generate session token: %v", err)
		return "", err
	}

	sessionExp := time.Now().Add(30 * 24 * time.Hour)
	sessionLastused := time.Now()
	session := models.Session{}

	userAgent := c.Request().Header.Get("User-Agent")
	ipAddress := c.RealIP()

	uaEnc, err := newCrypto.EncryptData([]byte(userAgent), "AES-GCM")
	if err != nil {
		logger.Errorf("Failed to encrypt user agent: %v", err)
		return "", err
	}

	uaPseudo, err := newCrypto.HashData([]byte(userAgent), "HMAC-SHA-256")
	if err != nil {
		logger.Errorf("Failed to hash user agent: %v", err)
		return "", err
	}

	ipAddressEnc, err := newCrypto.EncryptData([]byte(ipAddress), "AES-GCM")
	if err != nil {
		logger.Errorf("Failed to encrypt IP address: %v", err)
		return "", err
	}

	ipAddressPseudo, err := newCrypto.HashData([]byte(ipAddress), "HMAC-SHA-256")
	if err != nil {
		logger.Errorf("Failed to hash IP address: %v", err)
		return "", err
	}

	if err := db.Conn.Where(
		"user_id = ? AND ip_address_pseudonym = ? AND user_agent_pseudonym = ?", user.ID, ipAddressPseudo, uaPseudo).
		Assign(models.Session{
			UserID:             user.ID,
			Token:              sessionToken,
			LastUsedAt:         &sessionLastused,
			ExpiresAt:          &sessionExp,
			UserAgentEncrypted: &uaEnc,
			UserAgentPseudonym: &uaPseudo,
			IPAddressEncrypted: &ipAddressEnc,
			IPAddressPseudonym: &ipAddressPseudo,
		}).FirstOrCreate(&session).Error; err != nil {
		logger.Errorf("Failed to create session: %v", err)
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "https://queuedroid.com",
		"iat": time.Now().Unix(),
		"sub": user.AccountID,
		"aud": "https://api.queuedroid.com",
		"jti": sessionToken,
		"sid": session.ID,
		"uid": user.ID,
		"exp": session.ExpiresAt.Unix(),
	})

	tokenString, err := token.SignedString([]byte(commons.GetEnv("JWT_SECRET", "default_very_secret_key")))
	if err != nil {
		logger.Errorf("Failed to sign token: %v", err)
		return "", err
	}

	return tokenString, nil
}

// SignupHandler godoc
// @Summary      Register a new user
// @Description  Creates a new user account.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        signupRequest  body  SignupRequest  true  "Signup request payload"
// @Success      201 {object} AuthResponse 	 "Signup successful"
// @Failure      400 {object} echo.HTTPError     "Bad request, missing required fields"
// @Failure      409 {object} echo.HTTPError     "Duplicate user"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/auth/signup [post]
func SignupHandler(c echo.Context) error {
	logger := c.Logger()

	rmqClient, err := rabbitmq.NewClient(rabbitmq.RabbitMQConfig{})
	if err != nil {
		logger.Error("Failed to initialize RabbitMQ client:", err)
		return echo.ErrInternalServerError
	}

	var req SignupRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid signup request payload:", err)
		return echo.ErrBadRequest
	}

	if req.Email == "" {
		logger.Error("Email is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "email field is required",
		}
	}

	if req.CountryCode == "" {
		logger.Error("Country code is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "country_code field is required",
		}
	}

	if req.Password == "" {
		logger.Error("Password is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "password field is required",
		}
	}

	if err := passwordcheck.ValidatePassword(c.Request().Context(), req.Password); err != nil {
		logger.Error("Password validation failed: ", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("Invalid password: %v", err.Error()),
		}
	}

	countryCodeNum := phonenumbers.GetCountryCodeForRegion(req.CountryCode)
	if countryCodeNum == 0 {
		logger.Error("Invalid country code.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "country_code field must be a valid ISO 3166-1 alpha-2 country code.",
		}
	}

	newCrypto := crypto.NewCrypto()

	emailPseudo, err := newCrypto.HashData([]byte(req.Email), "HMAC-SHA-256")
	if err != nil {
		logger.Errorf("Failed to hash email for pseudonym: %v", err)
		return echo.ErrInternalServerError
	}

	count := db.Conn.Where("email_pseudonym = ?", emailPseudo).First(&models.User{}).RowsAffected
	if count > 0 {
		logger.Errorf("This email is already registered.")
		return &echo.HTTPError{
			Code:    http.StatusConflict,
			Message: "This email is already registered, please try another one.",
		}
	}

	hash, err := newCrypto.HashPassword(req.Password)
	if err != nil {
		logger.Errorf("Failed to hash password: %v", err)
		return echo.ErrInternalServerError
	}

	aid, err := crypto.GenerateRandomString("acct_", 16, "hex")
	if err != nil {
		logger.Errorf("Failed to generate account ID: %v", err)
		return echo.ErrInternalServerError
	}

	att, err := crypto.GenerateRandomString("", 32, "hex")
	if err != nil {
		logger.Errorf("Failed to generate account token: %v", err)
		return echo.ErrInternalServerError
	}

	emailEncrypted, err := newCrypto.EncryptData([]byte(req.Email), "AES-GCM")
	if err != nil {
		logger.Errorf("Failed to encrypt email: %v", err)
		return echo.ErrInternalServerError
	}

	countryCodeEncrypted, err := newCrypto.EncryptData([]byte(req.CountryCode), "AES-GCM")
	if err != nil {
		logger.Errorf("Failed to encrypt country code: %v", err)
		return echo.ErrInternalServerError
	}

	var fullNameEncrypted []byte
	if req.FullName != nil && *req.FullName != "" {
		var err error
		fullNameEncrypted, err = newCrypto.EncryptData([]byte(*req.FullName), "AES-GCM")
		if err != nil {
			logger.Errorf("Failed to encrypt full name: %v", err)
			return echo.ErrInternalServerError
		}
	}

	user := models.User{
		AccountID:            aid,
		AccountToken:         att,
		EmailEncrypted:       emailEncrypted,
		EmailPseudonym:       emailPseudo,
		Password:             hash,
		FullNameEncrypted:    &fullNameEncrypted,
		CountryCodeEncrypted: countryCodeEncrypted,
	}

	stat := models.Stats{
		Type:        models.StatsTypeSignup,
		CountryCode: &req.CountryCode,
	}

	plan := models.Plan{}

	if err := db.Conn.Where("name = ?", models.FreePlan).First(&plan).Error; err != nil {
		logger.Errorf("Failed to find free plan: %v", err)
		return echo.ErrInternalServerError
	}

	tx := db.Conn.Begin()
	if tx.Error != nil {
		logger.Errorf("Transaction begin failed: %v", tx.Error)
		return echo.ErrInternalServerError
	}

	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create user: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Create(&stat).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create stats: %v", err)
		return echo.ErrInternalServerError
	}

	subscription := models.Subscription{
		Status:    models.ActiveSubscription,
		StartedAt: time.Now(),
		UserID:    user.ID,
		PlanID:    plan.ID,
	}

	if err := tx.Create(&subscription).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create subscription: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.CreateVhost(user.AccountID); err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create RabbitMQ vhost: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.CreateUser(user.AccountID, user.AccountToken, []string{}); err != nil {
		rmqClient.DeleteVhost(user.AccountID)
		tx.Rollback()
		logger.Errorf("Failed to create RabbitMQ user: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.SetPermissions(user.AccountID, user.AccountID, ".*", ".*", ".*"); err != nil {
		rmqClient.DeleteUser(user.AccountID)
		rmqClient.DeleteVhost(user.AccountID)
		tx.Rollback()
		logger.Errorf("Failed to set RabbitMQ permissions: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.SetUserLimit(user.AccountID, 1, 1); err != nil {
		rmqClient.DeleteUser(user.AccountID)
		rmqClient.DeleteVhost(user.AccountID)
		tx.Rollback()
		logger.Errorf("Failed to set RabbitMQ user limits: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		logger.Errorf("Transaction commit failed: %v", err)
		return echo.ErrInternalServerError
	}

	verificationToken, err := crypto.GenerateRandomString("evt_", 32, "hex")
	if err != nil {
		logger.Errorf("Failed to generate verification token: %v", err)
		return echo.ErrInternalServerError
	}

	verificationExpiresAt := time.Now().Add(24 * time.Hour)
	verification := models.EmailVerification{
		UserID:    user.ID,
		Token:     verificationToken,
		ExpiresAt: verificationExpiresAt,
		IsUsed:    false,
	}

	if err := db.Conn.Create(&verification).Error; err != nil {
		logger.Errorf("Failed to create verification record: %v", err)
	}

	sessionToken, err := generateSessionToken(c, user, *newCrypto)
	if err != nil {
		logger.Errorf("Failed to generate session token after signup: %v", err)
		return echo.ErrInternalServerError
	}

	baseUrl := commons.GetEnv("BASE_URL", "https://api.queuedroid.com")
	verifyLink := commons.GetEnv("EMAIL_VERIFICATION_URL", "https://queuedroid.com") + "/verify-email?token=" + verificationToken
	vars := map[string]any{
		"verification_link": verifyLink,
		"base_url":          baseUrl,
		"expiration_hours":  "24",
	}

	if req.FullName != nil && *req.FullName != "" {
		vars["name"] = *req.FullName
	}

	go notifications.DispatchNotification(notifications.Email, notifications.SMTP, notifications.NotificationData{
		To:        req.Email,
		ToName:    req.FullName,
		Subject:   "Welcome to Queuedroid!",
		Template:  "welcome-with-verification",
		Variables: vars,
	})

	logger.Infof("User signed up successfully")
	return c.JSON(http.StatusCreated, AuthResponse{
		SessionToken: sessionToken,
		Message:      "Signup successful",
	})
}

// LoginHandler godoc
// @Summary      Login a user
// @Description  Authenticates a user and returns a token.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        loginRequest  body  LoginRequest  true  "Login request payload"
// @Success      200 {object} AuthResponse 	 "Login successful"
// @Failure      400 {object} echo.HTTPError     "Bad request, missing required fields"
// @Failure      401 {object} echo.HTTPError     "Unauthorized"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/auth/login [post]
func LoginHandler(c echo.Context) error {
	logger := c.Logger()

	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid login request payload:", err)
		return echo.ErrBadRequest
	}

	if req.Email == "" {
		logger.Error("Email is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "email field is required",
		}
	}

	if req.Password == "" {
		logger.Error("Password is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "password field is required",
		}
	}

	newCrypto := crypto.NewCrypto()
	user := models.User{}

	emailPseudo, err := newCrypto.HashData([]byte(req.Email), "HMAC-SHA-256")
	if err != nil {
		logger.Errorf("Failed to hash email: %v", err)
		return echo.ErrInternalServerError
	}

	if err := db.Conn.Where("email_pseudonym = ?", emailPseudo).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("User not found.")
			return &echo.HTTPError{
				Code:    http.StatusUnauthorized,
				Message: "Credentials are incorrect, please check your email and password",
			}
		}

		logger.Errorf("Failed to find user: %v", err)
		return echo.ErrInternalServerError
	}
	invalid_password := newCrypto.VerifyPassword(req.Password, user.Password)
	if invalid_password != nil {
		logger.Error("Password verification failed.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Credentials are incorrect, please check your email and password",
		}
	}

	sessionToken, err := generateSessionToken(c, user, *newCrypto)
	if err != nil {
		logger.Errorf("Failed to generate session token after login: %v", err)
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, AuthResponse{
		SessionToken: sessionToken,
		Message:      "Login successful",
	})
}

// LogoutHandler godoc
// @Summary      Logout a user
// @Description  Logs out a user and invalidates the session.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Success      204 "Logout successful"
// @Failure      401 {object} echo.HTTPError     "Unauthorized"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/auth/logout [post]
func LogoutHandler(c echo.Context) error {
	logger := c.Logger()

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	if err := db.Conn.Unscoped().Delete(&session).Error; err != nil {
		logger.Errorf("Failed to delete session: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("User logged out successfully")
	return c.NoContent(http.StatusNoContent)
}

// ForgotPasswordHandler godoc
// @Summary      Request password reset
// @Description  Sends a password reset email to the user's registered email address
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        forgotPasswordRequest  body  ForgotPasswordRequest  true  "Forgot password request"
// @Success      200 {object} GenericResponse "Password reset email sent successfully"
// @Failure      400 {object} echo.HTTPError  "Bad request"
// @Failure      404 {object} echo.HTTPError  "User not found"
// @Failure      429 {object} echo.HTTPError  "Too many requests"
// @Failure      500 {object} echo.HTTPError  "Internal server error"
// @Router       /v1/auth/forgot-password [post]
func ForgotPasswordHandler(c echo.Context) error {
	logger := c.Logger()

	var req ForgotPasswordRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid forgot password request payload:", err)
		return echo.ErrBadRequest
	}

	if req.Email == "" {
		logger.Error("Email is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "email field is required",
		}
	}

	newCrypto := crypto.NewCrypto()
	user := models.User{}

	emailPseudo, err := newCrypto.HashData([]byte(req.Email), "HMAC-SHA-256")
	if err != nil {
		logger.Errorf("Failed to hash email: %v", err)
		return echo.ErrInternalServerError
	}

	if err := db.Conn.Where("email_pseudonym = ?", emailPseudo).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("User not found for password reset.")
			return c.JSON(http.StatusOK, GenericResponse{
				Message: "If the email you entered is linked to an account, you’ll receive password reset instructions in your mail. Be sure to check your inbox and spam folder.",
			})
		}

		logger.Errorf("Failed to find user: %v", err)
		return echo.ErrInternalServerError
	}

	recentReset := models.EmailVerification{}
	if err := db.Conn.Where("user_id = ? AND created_at > ?", user.ID, time.Now().Add(-5*time.Minute)).
		First(&recentReset).Error; err == nil {
		logger.Info("Recent password reset email already sent")
		return &echo.HTTPError{
			Code:    http.StatusTooManyRequests,
			Message: "Please wait 5 minutes before requesting another password reset email",
		}
	}

	token, err := crypto.GenerateRandomString("prt_", 32, "hex")
	if err != nil {
		logger.Errorf("Failed to generate password reset token: %v", err)
		return echo.ErrInternalServerError
	}

	expiresAt := time.Now().Add(24 * time.Hour)

	passwordReset := models.EmailVerification{}
	if err := db.Conn.Where("user_id = ? AND is_used = ?", user.ID, false).
		Assign(models.EmailVerification{
			UserID:    user.ID,
			Token:     token,
			ExpiresAt: expiresAt,
			IsUsed:    false,
		}).FirstOrCreate(&passwordReset).Error; err != nil {
		logger.Errorf("Failed to check existing password reset tokens: %v", err)
		return echo.ErrInternalServerError
	}

	emailBytes, err := newCrypto.DecryptData(user.EmailEncrypted, "AES-GCM")
	if err != nil {
		logger.Errorf("Failed to decrypt user email: %v", err)
		return echo.ErrInternalServerError
	}
	email := string(emailBytes)
	fullName := ""

	baseUrl := commons.GetEnv("BASE_URL", "https://api.queuedroid.com")
	resetLink := commons.GetEnv("EMAIL_VERIFICATION_URL", "https://queuedroid.com") + "/reset-password?token=" + token
	vars := map[string]any{
		"reset_link":       resetLink,
		"base_url":         baseUrl,
		"expiration_hours": "24",
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
		Subject:   "Reset Your QueueDroid Password",
		Template:  "password-reset",
		Variables: vars,
	})

	logger.Infof("Password reset email sent successfully.")
	return c.JSON(http.StatusOK, GenericResponse{
		Message: "If the email you entered is linked to an account, you'll " +
			"receive password reset instructions in your mail. Be sure to check your inbox and spam folder.",
	})
}

// ResetPasswordHandler godoc
// @Summary      Reset password
// @Description  Resets the user's password using the token sent via email
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        resetPasswordRequest  body  ResetPasswordRequest  true  "Password reset request"
// @Success      200 {object} GenericResponse "Password reset successfully"
// @Failure      400 {object} echo.HTTPError  "Bad request or invalid token"
// @Failure      410 {object} echo.HTTPError  "Token expired"
// @Failure      500 {object} echo.HTTPError  "Internal server error"
// @Router       /v1/auth/reset-password [post]
func ResetPasswordHandler(c echo.Context) error {
	logger := c.Logger()

	var req ResetPasswordRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid password reset request payload:", err)
		return echo.ErrBadRequest
	}

	if req.Token == "" {
		logger.Error("Password reset token is required")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "token field is required",
		}
	}

	if req.NewPassword == "" {
		logger.Error("New password is required")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "new_password field is required",
		}
	}

	if err := passwordcheck.ValidatePassword(c.Request().Context(), req.NewPassword); err != nil {
		logger.Error("New password validation failed: ", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid new password: " + err.Error(),
		}
	}

	passwordReset := models.EmailVerification{}

	if err := db.Conn.Preload("User").
		Where("token = ? AND is_used = ?", req.Token, false).
		First(&passwordReset).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("Invalid or already used password reset token")
			return &echo.HTTPError{
				Code:    http.StatusBadRequest,
				Message: "Invalid or already used password reset token",
			}
		}
		logger.Errorf("Failed to find password reset record: %v", err)
		return echo.ErrInternalServerError
	}

	if time.Now().After(passwordReset.ExpiresAt) {
		logger.Error("Password reset token has expired")
		return &echo.HTTPError{
			Code:    http.StatusGone,
			Message: "Password reset token has expired. Please request a new one.",
		}
	}

	newCrypto := crypto.NewCrypto()

	if err := newCrypto.VerifyPassword(req.NewPassword, passwordReset.User.Password); err == nil {
		logger.Error("New password is the same as current password.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "New password must be different from the current password",
		}
	}

	hashedNewPassword, err := newCrypto.HashPassword(req.NewPassword)
	if err != nil {
		logger.Errorf("Failed to hash new password: %v", err)
		return echo.ErrInternalServerError
	}

	tx := db.Conn.Begin()
	if tx.Error != nil {
		logger.Errorf("Transaction begin failed: %v", tx.Error)
		return echo.ErrInternalServerError
	}

	if err := tx.Model(&passwordReset.User).Update("password", hashedNewPassword).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to update user password: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Model(&passwordReset).Update("is_used", true).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to mark password reset token as used: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Unscoped().Where("user_id = ?", passwordReset.User.ID).Delete(&models.Session{}).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to invalidate user sessions: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		logger.Errorf("Transaction commit failed: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("Password reset successful for user ID: %d", passwordReset.User.ID)
	return c.JSON(http.StatusOK, GenericResponse{
		Message: "Password reset successfully. Please log in with your new password.",
	})
}

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
			UserID:    user.ID,
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
