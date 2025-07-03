// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"net/http"
	"qdroid-server/db"
	"qdroid-server/models"

	"github.com/labstack/echo/v4"
)

// GetUserHandler godoc
// @Summary      Get user details
// @Description  Retrieves the details of the authenticated user.
// @Tags         users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Success      200 {object}  GetUserResponse 	 "User retrieved successfully"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/users/ [get]
func GetUserHandler(c echo.Context) error {
	logger := c.Logger()

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	user := models.User{}
	if err := db.Conn.Where("id = ?", session.UserID).First(&user).Error; err != nil {
		logger.Errorf("Failed to find user: %v", err)
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, GetUserResponse{
		Message:      "User retrieved successfully",
		AccountID:    user.AccountID,
		AccountToken: user.AccountToken,
		Email:        user.Email,
		PhoneNumber:  user.PhoneNumber,
		FullName:     user.FullName,
	})
}
