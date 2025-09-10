// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"errors"
	"net/http"
	"qdroid-server/db"
	"qdroid-server/middlewares"
	"qdroid-server/models"
	"time"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

func calculateUsagePercentage(current int, limit *uint) *float64 {
	if limit == nil {
		return nil
	}
	if *limit == 0 {
		return nil
	}
	percentage := (float64(current) / float64(*limit)) * 100
	return &percentage
}

// GetSubscriptionHandler godoc
// @Summary      Get user subscription details
// @Description  Retrieves detailed information about the authenticated user's subscription, including plan details, usage limits, and subscription status.
// @Tags         subscriptions
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Success      200 {object}  GetSubscriptionResponse "Subscription details retrieved successfully"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      404 {object} echo.HTTPError     "No subscription found for the user"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/subscriptions [get]
func GetSubscriptionHandler(c echo.Context) error {
	logger := c.Logger()

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	subscription := models.Subscription{}
	if err := db.Conn.Preload("Plan").Where("user_id = ?", user.ID).First(&subscription).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warnf("No subscription found for user ID %d", user.ID)
			return &echo.HTTPError{
				Code:    http.StatusNotFound,
				Message: "No subscription found for this user",
			}
		}
		logger.Errorf("Failed to fetch user subscription: %v", err)
		return echo.ErrInternalServerError
	}

	var daysRemaining *int
	if subscription.ExpiresAt != nil {
		remaining := int(time.Until(*subscription.ExpiresAt).Hours() / 24)
		if remaining < 0 {
			remaining = 0
		}
		daysRemaining = &remaining
	}

	planDetails := PlanDetails{
		ID:                  subscription.Plan.ID,
		Name:                string(subscription.Plan.Name),
		Price:               subscription.Plan.Price,
		Currency:            subscription.Plan.Currency,
		DurationInDays:      subscription.Plan.DurationInDays,
		MaxProjects:         subscription.Plan.MaxProjects,
		MaxMessagesPerMonth: subscription.Plan.MaxMessagesPerMonth,
		MaxAPIKeys:          subscription.Plan.MaxAPIKeys,
	}

	var expiresAtStr *string
	if subscription.ExpiresAt != nil {
		expiresAtFormatted := subscription.ExpiresAt.Format(time.RFC3339)
		expiresAtStr = &expiresAtFormatted
	}

	response := GetSubscriptionResponse{
		Message:       "Subscription details retrieved successfully",
		ID:            subscription.ID,
		Status:        string(subscription.Status),
		AutoRenew:     subscription.AutoRenew,
		StartedAt:     subscription.StartedAt.Format(time.RFC3339),
		ExpiresAt:     expiresAtStr,
		DaysRemaining: daysRemaining,
		Plan:          planDetails,
		CreatedAt:     subscription.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     subscription.UpdatedAt.Format(time.RFC3339),
	}

	return c.JSON(http.StatusOK, response)
}

// GetSubscriptionSummaryHandler godoc
// @Summary      Get subscription summary with usage statistics
// @Description  Retrieves a summary of the user's subscription including current usage statistics, limits, and available actions.
// @Tags         subscriptions
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Success      200 {object}  GetSubscriptionSummaryResponse "Subscription summary retrieved successfully"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      404 {object} echo.HTTPError     "No subscription found for the user"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/subscriptions/summary [get]
func GetSubscriptionSummaryHandler(c echo.Context) error {
	logger := c.Logger()

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	subscription := models.Subscription{}
	if err := db.Conn.Preload("Plan").Where("user_id = ?", user.ID).First(&subscription).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warnf("No subscription found for user ID %d", user.ID)
			return &echo.HTTPError{
				Code:    http.StatusNotFound,
				Message: "No subscription found for this user",
			}
		}
		logger.Errorf("Failed to fetch user subscription: %v", err)
		return echo.ErrInternalServerError
	}

	var currentExchangeCount int64
	if err := db.Conn.Model(&models.Exchange{}).Where("user_id = ?", user.ID).Count(&currentExchangeCount).Error; err != nil {
		logger.Errorf("Failed to count exchanges: %v", err)
		return echo.ErrInternalServerError
	}

	var currentAPIKeyCount int64
	if err := db.Conn.Model(&models.APIKey{}).Where("user_id = ?", user.ID).Count(&currentAPIKeyCount).Error; err != nil {
		logger.Errorf("Failed to count API keys: %v", err)
		return echo.ErrInternalServerError
	}

	now := time.Now()
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	var currentMessageCount int64
	if err := db.Conn.Model(&models.EventLog{}).
		Where("user_id = ? AND category = ? AND created_at >= ?", user.ID, models.Message, startOfMonth).
		Count(&currentMessageCount).Error; err != nil {
		logger.Errorf("Failed to count messages: %v", err)
		return echo.ErrInternalServerError
	}

	usage := UsageDetails{
		Projects: UsageItem{
			Current:    int(currentExchangeCount),
			Limit:      subscription.Plan.MaxProjects,
			Percentage: calculateUsagePercentage(int(currentExchangeCount), subscription.Plan.MaxProjects),
		},
		APIKeys: UsageItem{
			Current:    int(currentAPIKeyCount),
			Limit:      subscription.Plan.MaxAPIKeys,
			Percentage: calculateUsagePercentage(int(currentAPIKeyCount), subscription.Plan.MaxAPIKeys),
		},
		MessagesThisMonth: UsageItem{
			Current:    int(currentMessageCount),
			Limit:      subscription.Plan.MaxMessagesPerMonth,
			Percentage: calculateUsagePercentage(int(currentMessageCount), subscription.Plan.MaxMessagesPerMonth),
		},
	}

	availableActions := []string{}

	if subscription.Plan.MaxProjects == nil || currentExchangeCount < int64(*subscription.Plan.MaxProjects) {
		availableActions = append(availableActions, "create_project")
	}

	if subscription.Plan.MaxAPIKeys == nil || currentAPIKeyCount < int64(*subscription.Plan.MaxAPIKeys) {
		availableActions = append(availableActions, "create_api_key")
	}

	if subscription.Plan.MaxMessagesPerMonth == nil || currentMessageCount < int64(*subscription.Plan.MaxMessagesPerMonth) {
		availableActions = append(availableActions, "send_message")
	}

	var daysRemaining *int
	var isExpiringSoon bool
	if subscription.ExpiresAt != nil {
		remaining := max(int(time.Until(*subscription.ExpiresAt).Hours()/24), 0)
		daysRemaining = &remaining
		isExpiringSoon = remaining <= 7 && remaining > 0
	}

	response := GetSubscriptionSummaryResponse{
		Message:          "Subscription summary retrieved successfully",
		PlanName:         string(subscription.Plan.Name),
		Status:           string(subscription.Status),
		AutoRenew:        subscription.AutoRenew,
		DaysRemaining:    daysRemaining,
		IsExpiringSoon:   isExpiringSoon,
		Usage:            usage,
		AvailableActions: availableActions,
	}

	return c.JSON(http.StatusOK, response)
}
