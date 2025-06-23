// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"errors"
	"net/http"
	"qdroid-server/commons"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// LoginHandler godoc
// @Summary      Login a user
// @Description  Authenticates a user and returns a token.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        loginRequest  body  LoginRequest  true  "Login request payload"
// @Success      200 {object} LoginResponse 	 "Login successful"
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

	session_token, err := crypto.GenerateHexID("st_long_", 32)
	if err != nil {
		logger.Errorf("Failed to generate session token: %v", err)
		return echo.ErrInternalServerError
	}

	session_exp := time.Now().Add(30 * 24 * time.Hour)
	session_lastused := time.Now()
	session := models.Session{}

	if err := db.Conn.Where("user_id = ?", user.ID).Assign(models.Session{
		Token:      session_token,
		LastUsedAt: &session_lastused,
		ExpiresAt:  &session_exp,
	}).FirstOrCreate(&session).Error; err != nil {
		logger.Errorf("Failed to create session: %v", err)
		return echo.ErrInternalServerError
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "https://qdroid-server.com",
		"iat": time.Now().Unix(),
		"sub": user.AccountID,
		"aud": "https://api.qdroid-server.com",
		"jti": session_token,
		"sid": session.ID,
		"uid": user.ID,
		"exp": session.ExpiresAt.Unix(),
	})
	tokenString, err := token.SignedString([]byte(commons.GetEnv("JWT_SECRET", "default_very_secret_key")))
	if err != nil {
		logger.Errorf("Failed to sign token: %v", err)
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, LoginResponse{SessionToken: tokenString, Message: "Login successful"})
}
