// SPX-License-Identifier: GPL-3.0-only

package middlewares

import (
	"errors"
	"net/http"
	"qdroid-server/commons"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/models"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type AuthMethod int

const (
	AuthMethodSession AuthMethod = iota
	AuthMethodAPIKey
)

func VerifyAuthMiddleware(authMethods ...AuthMethod) func(echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			logger := c.Logger()

			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				logger.Error("Authorization header missing or invalid.")
				return &echo.HTTPError{
					Code:    http.StatusUnauthorized,
					Message: "Bearer token is required",
				}
			}

			if len(authMethods) == 0 {
				authMethods = []AuthMethod{AuthMethodSession}
			}

			isMethodAllowed := func(method AuthMethod) bool {
				return slices.Contains(authMethods, method)
			}

			if isMethodAllowed(AuthMethodSession) {
				if after, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
					sessionToken := after

					token, err := jwt.Parse(sessionToken, func(t *jwt.Token) (any, error) {
						if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
							return nil, errors.New("unexpected signing method")
						}
						return []byte(commons.GetEnv("JWT_SECRET", "default_very_secret_key")), nil
					})

					if err == nil && token.Valid {
						claims, ok := token.Claims.(jwt.MapClaims)
						if ok {
							sessionID := claims["sid"]
							userID := claims["uid"]
							tokenID := claims["jti"]

							session := models.Session{}
							err = db.Conn.Where("id = ? AND user_id = ? AND token = ?", sessionID, userID, tokenID).First(&session).Error
							if err == nil && !session.ExpiresAt.Before(time.Now()) {
								now := time.Now()
								session.LastUsedAt = &now

								if err := db.Conn.Save(&session).Error; err != nil {
									logger.Error("Failed to update session LastUsedAt: ", err)
								}

								c.Set("session", session)
								c.Set("auth_method", AuthMethodSession)
								return next(c)
							}
						}
					}
				}
			}

			if isMethodAllowed(AuthMethodAPIKey) {
				if after, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
					apiKeyValue := after
					keyIDLength := 35

					if apiKeyValue != "" && strings.HasPrefix(apiKeyValue, "ak_") {
						if len(apiKeyValue) >= keyIDLength {
							keyID := apiKeyValue[:keyIDLength]

							apiKey := models.APIKey{}
							err := db.Conn.Where("key_id = ?", keyID).First(&apiKey).Error
							if err == nil {
								if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
									logger.Error("API key expired.")
								} else {
									cryptoInstance := crypto.NewCrypto()
									if err := cryptoInstance.VerifyPassword(apiKeyValue, apiKey.HashedKey); err == nil {
										now := time.Now()
										apiKey.LastUsedAt = &now
										if err := db.Conn.Save(&apiKey).Error; err != nil {
											logger.Error("Failed to update API key LastUsedAt: ", err)
										}

										c.Set("api_key", apiKey)
										c.Set("auth_method", AuthMethodAPIKey)
										return next(c)
									}
								}
							}
						}
					}
				}
			}

			logger.Error("Authentication failed.")
			return &echo.HTTPError{
				Code:    http.StatusUnauthorized,
				Message: "Invalid or expired authentication token",
			}
		}
	}
}

func GetAuthenticatedUser(c echo.Context) (*models.User, error) {
	authMethod := c.Get("auth_method")

	switch authMethod {
	case AuthMethodSession:
		if session, ok := c.Get("session").(models.Session); ok {
			var user models.User
			err := db.Conn.Where("id = ?", session.UserID).First(&user).Error
			if err != nil {
				return nil, err
			}
			return &user, nil
		}
	case AuthMethodAPIKey:
		if apiKey, ok := c.Get("api_key").(models.APIKey); ok {
			var user models.User
			err := db.Conn.Where("id = ?", apiKey.UserID).First(&user).Error
			if err != nil {
				return nil, err
			}
			return &user, nil
		}
	}

	return nil, errors.New("no authenticated user found")
}

func GetAuthenticatedUserID(c echo.Context) (uint, error) {
	user, err := GetAuthenticatedUser(c)
	if err != nil {
		return 0, err
	}
	return user.ID, nil
}
