// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"errors"
	"net/http"
	"qdroid-server/commons"
	"qdroid-server/db"
	"qdroid-server/models"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// GetOneAPIKeyHandler godoc
// @Summary      Get a user's API key
// @Description  Retrieves the API key for the authenticated user.
// @Description  Note: The Authorization header must contain the session_token obtained from the login endpoint, in the format "Bearer {token}".
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string  true  "Bearer {token} (session_token from login)"
// @Success      200 {object} GetOneAPIKeyResponse "API key retrieved successfully"
// @Failure      401 {object} echo.HTTPError "Unauthorized"
// @Failure      404 {object} echo.HTTPError "Not Found"
// @Failure      500 {object} echo.HTTPError "Internal Server Error"
// @Router       /v1/auth/apikey [get]
func GetOneAPIKeyHandler(c echo.Context) error {
	logger := c.Logger()

	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		logger.Error("Authorization header missing or invalid.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Authorization token is required",
		}
	}
	sessionToken := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(sessionToken, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(commons.GetEnv("JWT_SECRET", "default_very_secret_key")), nil
	})
	if err != nil || !token.Valid {
		logger.Error("JWT Failed to parse or is invalid: ", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		logger.Error("Failed to parse JWT claims.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid session token, please login again",
		}
	}

	sessionID := claims["sid"]
	userID := claims["uid"]
	tokenID := claims["jti"]

	session := models.Session{}
	err = db.Conn.Where("id = ? AND user_id = ? AND token = ?", sessionID, userID, tokenID).First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) || session.ExpiresAt.Before(time.Now()) {
		logger.Error("Session not found or expired.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	apiKey := models.APIKey{}
	err = db.Conn.Where("user_id = ?", session.UserID).First(&apiKey).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Error("User has no API key.")
		return &echo.HTTPError{
			Code:    http.StatusNotFound,
			Message: "User has no registered API key, please generate one",
		}
	}

	return c.JSON(http.StatusOK, GetOneAPIKeyResponse{
		Token:      apiKey.Token,
		Label:      apiKey.Label,
		Seen:       apiKey.Seen,
		LastUsedAt: apiKey.LastUsedAt,
		CreatedAt:  apiKey.CreatedAt,
		UpdatedAt:  apiKey.UpdatedAt,
	})
}
