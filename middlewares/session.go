// SPX-License-Identifier: GPL-3.0-only

package middlewares

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

func VerifySessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
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
				Message: "Invalid or expired session token, please login again",
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

		now := time.Now()
		session.LastUsedAt = &now

		if err := db.Conn.Save(&session).Error; err != nil {
			logger.Error("Failed to update session LastUsedAt: ", err)
		}

		c.Set("session", session)
		return next(c)
	}
}
