// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"qdroid-server/commons"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/models"
	"qdroid-server/passwordcheck"
	"qdroid-server/rabbitmq"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/nyaruka/phonenumbers"
	"gorm.io/gorm"
)

func generateSessionToken(c echo.Context, user models.User) (string, error) {
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

	if err := db.Conn.Where("user_id = ?", user.ID).Assign(models.Session{
		UserID:     user.ID,
		Token:      sessionToken,
		LastUsedAt: &sessionLastused,
		ExpiresAt:  &sessionExp,
		UserAgent:  &userAgent,
		IPAddress:  &ipAddress,
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

	if req.PhoneNumber != nil && *req.PhoneNumber != "" {
		parsedNumber, err := phonenumbers.Parse(*req.PhoneNumber, req.CountryCode)
		if err != nil {
			logger.Error("Failed to parse phone number: ", err)
			return &echo.HTTPError{
				Code:    http.StatusBadRequest,
				Message: "phone_number field must be a valid E.164 phone number. Please ensure it starts with a '+' followed by the country code and national number.",
			}
		}

		if !phonenumbers.IsValidNumber(parsedNumber) {
			logger.Error("Invalid phone number.")
			return &echo.HTTPError{
				Code:    http.StatusBadRequest,
				Message: "phone_number field must be a valid E.164 phone number. Please ensure it starts with a '+' followed by the country code and national number.",
			}
		}
	}

	countryCodeNum := phonenumbers.GetCountryCodeForRegion(req.CountryCode)
	fmt.Println("Country code number:", countryCodeNum)
	if countryCodeNum == 0 {
		logger.Error("Invalid country code.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "country_code field must be a valid ISO 3166-1 alpha-2 country code.",
		}
	}

	count := db.Conn.Where("email = ?", req.Email).First(&models.User{}).RowsAffected
	if count > 0 {
		logger.Errorf("This email is already registered.")
		return &echo.HTTPError{
			Code:    http.StatusConflict,
			Message: "This email is already registered, please try another one.",
		}
	}

	newCrypto := crypto.NewCrypto()
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

	user := models.User{
		AccountID:    aid,
		AccountToken: att,
		Email:        req.Email,
		Password:     hash,
		PhoneNumber:  req.PhoneNumber,
		FullName:     req.FullName,
		CountryCode:  req.CountryCode,
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

	if err := rmqClient.CreateVhost(user.AccountID); err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create RabbitMQ vhost: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.CreateUser(user.AccountID, user.AccountToken, []string{"management"}); err != nil {
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

	if err := tx.Commit().Error; err != nil {
		logger.Errorf("Transaction commit failed: %v", err)
		return echo.ErrInternalServerError
	}

	sessionToken, err := generateSessionToken(c, user)
	if err != nil {
		logger.Errorf("Failed to generate session token after signup: %v", err)
		return echo.ErrInternalServerError
	}

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
	err := db.Conn.Where("email = ?", req.Email).First(&user).Error

	if err != nil {
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

	sessionToken, err := generateSessionToken(c, user)
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
