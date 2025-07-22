// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"errors"
	"net/http"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/models"
	"time"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// CreateAPIKeyHandler godoc
// @Summary      Create API key
// @Description  Creates a new API key for the authenticated user.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Success      201 {object} CreateAPIKeyResponse "API key created successfully"
// @Failure      400 {object} echo.HTTPError     "Bad request, missing required fields"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      409 {object} echo.HTTPError     "Duplicate API key name detected"
// @Failure      404 {object} echo.HTTPError     "User not found"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/auth/api-keys [post]
func CreateAPIKeyHandler(c echo.Context) error {
	logger := c.Logger()

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	var req CreateAPIKeyRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid create/bind queue request payload:", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid request payload, please ensure it is well-formed and has content-type application/json header",
		}
	}

	if req.Name == "" {
		logger.Error("Name is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "name field is required",
		}
	}

	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		parsedTime, err := time.Parse("2006-01-02", *req.ExpiresAt)
		if err != nil {
			logger.Error("Invalid ExpiresAt format. Must be date-only:", err)
			return &echo.HTTPError{
				Code:    http.StatusBadRequest,
				Message: "expires_at must be a valid date in YYYY-MM-DD format",
			}
		}
		expiresAt = &parsedTime
	}

	user := models.User{}
	if err := db.Conn.Where("id = ?", session.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("User not found.")
			return &echo.HTTPError{
				Code:    http.StatusNotFound,
				Message: "User not found",
			}
		}
		logger.Errorf("Failed to find user: %v", err)
		return echo.ErrInternalServerError
	}

	count := db.Conn.Where("name = ?", req.Name).First(&models.APIKey{}).RowsAffected
	if count > 0 {
		logger.Errorf("This API key name is already registered.")
		return &echo.HTTPError{
			Code:    http.StatusConflict,
			Message: "This API key name is already registered, please try another one.",
		}
	}

	keyID, err := crypto.GenerateRandomString("ak_", 16, "hex")
	if err != nil {
		logger.Errorf("Failed to generate API key ID: %v", err)
		return echo.ErrInternalServerError
	}

	keySecret, err := crypto.GenerateRandomString("", 32, "hex")
	if err != nil {
		logger.Errorf("Failed to generate API key secret: %v", err)
		return echo.ErrInternalServerError
	}

	fullApiKey := keyID + keySecret

	newCrypto := crypto.NewCrypto()
	hashedKey, err := newCrypto.HashPassword(fullApiKey)
	if err != nil {
		logger.Errorf("Failed to hash API key: %v", err)
		return echo.ErrInternalServerError
	}

	apiKey := models.APIKey{
		Name:        req.Name,
		Description: req.Description,
		HashedKey:   hashedKey,
		KeyID:       keyID,
		UserID:      user.ID,
		ExpiresAt:   expiresAt,
	}

	if err := db.Conn.Create(&apiKey).Error; err != nil {
		logger.Errorf("Failed to create API key: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("API key created successfully.")

	var expiresAtStr *string
	if apiKey.ExpiresAt != nil {
		str := apiKey.ExpiresAt.Format("2006-01-02")
		expiresAtStr = &str
	}

	return c.JSON(http.StatusCreated, CreateAPIKeyResponse{
		APIKey:      fullApiKey,
		KeyID:       apiKey.KeyID,
		Name:        apiKey.Name,
		Description: apiKey.Description,
		ExpiresAt:   expiresAtStr,
		CreatedAt:   apiKey.CreatedAt.Format(time.RFC3339),
		Message:     "API key created successfully",
	})
}
