// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"fmt"
	"net/http"
	"qdroid-server/db"
	"qdroid-server/models"

	"github.com/labstack/echo/v4"
)

// GetPlansHandler godoc
// @Summary      Get available plans
// @Description  Retrieves all available subscription plans with monthly and yearly pricing options for display to clients.
// @Tags         plans
// @Accept       json
// @Produce      json
// @Success      200 {object}  GetPlansResponse "Plans retrieved successfully"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/plans [get]
func GetPlansHandler(c echo.Context) error {
	logger := c.Logger()

	var plans []models.Plan
	result := db.Conn.Find(&plans)
	if result.Error != nil {
		logger.Error("Failed to retrieve plans:", result.Error)
		return &echo.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to retrieve plans",
		}
	}

	var planOptions []PlanOption
	for _, plan := range plans {
		monthlyPrice := plan.Price
		discountPercentage := uint(10)
		yearlyPrice := monthlyPrice * 12

		if monthlyPrice > 0 {
			yearlyPrice = uint(float64(yearlyPrice) * (1 - float64(discountPercentage)/100))
		}

		var features []string
		switch plan.Name {
		case models.FreePlan:
			features = []string{
				"1 device connection",
				fmt.Sprintf("%d messages/month", *plan.MaxMessagesPerMonth),
				fmt.Sprintf("%d project(s)", *plan.MaxProjects),
				fmt.Sprintf("%d API key(s)", *plan.MaxAPIKeys),
				"Community support",
				"Standard analytics",
			}
		case models.PlusPlan:
			features = []string{
				"Unlimited device connections",
				"Unlimited messages/month",
				"Unlimited projects",
				"Unlimited API keys",
				"Priority support",
				"Advanced analytics",
			}
		default:
			features = []string{}
		}

		planOption := PlanOption{
			ID:   plan.ID,
			Name: string(plan.Name),
			Pricing: PlanPricing{
				Monthly:  monthlyPrice,
				Yearly:   yearlyPrice,
				Currency: plan.Currency,
			},
			Recommended: plan.Name == models.PlusPlan,
			Features:    features,
			Discount:    discountPercentage,
		}

		planOptions = append(planOptions, planOption)
	}

	response := GetPlansResponse{
		Message: "Plans retrieved successfully",
		Plans:   planOptions,
	}

	return c.JSON(http.StatusOK, response)
}
