// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/middlewares"
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
// @Failure      403 {object} echo.HTTPError     "Forbidden, no active subscription found or max API keys reached"
// @Failure      409 {object} echo.HTTPError     "Duplicate API key name detected"
// @Failure      404 {object} echo.HTTPError     "User not found"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/auth/api-keys [post]
func CreateAPIKeyHandler(c echo.Context) error {
	logger := c.Logger()

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
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

	subscription := models.Subscription{}
	if err := db.Conn.Preload("Plan").Where("user_id = ? AND status = ?",
		user.ID,
		models.ActiveSubscription).
		First(&subscription).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("No active subscription found for user.")
			return &echo.HTTPError{
				Code:    http.StatusForbidden,
				Message: "No active subscription found. Please subscribe to a plan to create API keys.",
			}
		}
		logger.Errorf("Failed to fetch user subscription: %v", err)
		return echo.ErrInternalServerError
	}

	if subscription.Plan.MaxAPIKeys != nil {
		var currentAPIKeyCount int64
		if err := db.Conn.Model(&models.APIKey{}).
			Where("user_id = ?", user.ID).
			Count(&currentAPIKeyCount).Error; err != nil {
			logger.Errorf("Failed to count user API keys: %v", err)
			return echo.ErrInternalServerError
		}

		if currentAPIKeyCount >= int64(*subscription.Plan.MaxAPIKeys) {
			logger.Errorf("User has reached the maximum number of API keys for their subscription plan.")
			return &echo.HTTPError{
				Code: http.StatusForbidden,
				Message: fmt.Sprintf(
					"You have reached the maximum number of API keys (%d) allowed for your %s subscription plan. "+
						"Please upgrade your plan to create more API keys.",
					*subscription.Plan.MaxAPIKeys,
					subscription.Plan.Name,
				),
			}
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

// GetAllAPIKeyHandler godoc
// @Summary      Get all API keys (paginated)
// @Description  Retrieves all API keys for the authenticated user, paginated.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        page     query   int  false  "Page number (default 1)"
// @Param        page_size query  int  false  "Page size (default 10, max 100)"
// @Success      200 {object} APIKeyListResponse "Paginated list of API keys"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/auth/api-keys [get]
func GetAllAPIKeyHandler(c echo.Context) error {
	logger := c.Logger()

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	page := 1
	pageSize := 10
	if p := c.QueryParam("page"); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &page); err != nil || page < 1 {
			page = 1
		}
	}
	if ps := c.QueryParam("page_size"); ps != "" {
		if _, err := fmt.Sscanf(ps, "%d", &pageSize); err != nil || pageSize < 1 {
			pageSize = 10
		}
	}
	if pageSize > 100 {
		pageSize = 100
	}

	var total int64
	var apiKeys []models.APIKey
	db.Conn.Model(&models.APIKey{}).Where("user_id = ?", user.ID).Count(&total)
	db.Conn.Where("user_id = ?", user.ID).
		Order("created_at desc").
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		Find(&apiKeys)

	var data []APIKeyDetails = []APIKeyDetails{}
	for _, key := range apiKeys {
		var lastUsedAtStr *string
		if key.LastUsedAt != nil {
			str := key.LastUsedAt.Format(time.RFC3339)
			lastUsedAtStr = &str
		}

		var expiresAtStr *string
		if key.ExpiresAt != nil {
			str := key.ExpiresAt.Format("2006-01-02")
			expiresAtStr = &str
		}

		data = append(data, APIKeyDetails{
			KeyID:       key.KeyID,
			Name:        key.Name,
			Description: key.Description,
			CreatedAt:   key.CreatedAt.Format(time.RFC3339),
			LastUsedAt:  lastUsedAtStr,
			ExpiresAt:   expiresAtStr,
		})
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	return c.JSON(http.StatusOK, APIKeyListResponse{
		Data: data,
		Pagination: PaginationDetails{
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		},
		Message: "API keys retrieved successfully",
	})
}

// DeleteAPIKeyHandler godoc
// @Summary      Delete API key
// @Description  Deletes an existing API key for the authenticated user.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        key_id        path    string  true  "API Key ID"
// @Success      200 {object} GenericResponse "API key deleted successfully"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      404 {object} echo.HTTPError     "API key not found"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/auth/api-keys/{key_id} [delete]
func DeleteAPIKeyHandler(c echo.Context) error {
	logger := c.Logger()
	keyID := c.Param("key_id")

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	apiKey := models.APIKey{}
	if err := db.Conn.Where("key_id = ? AND user_id = ?", keyID, user.ID).First(&apiKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("API key not found.")
			return &echo.HTTPError{
				Code:    http.StatusNotFound,
				Message: "API key not found",
			}
		}

		logger.Errorf("Failed to find API key: %v", err)
		return echo.ErrInternalServerError
	}

	if err := db.Conn.Unscoped().Delete(&apiKey).Error; err != nil {
		logger.Errorf("Failed to delete API key: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("API key deleted successfully.")
	return c.JSON(http.StatusOK, GenericResponse{
		Message: "API key deleted successfully",
	})
}
