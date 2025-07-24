// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"net/http"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/middlewares"
	"qdroid-server/models"
	"qdroid-server/rabbitmq"

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

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
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

// DeleteAccountHandler godoc
// @Summary      Delete user account
// @Description  Deletes the authenticated user's account after password confirmation. This action is irreversible and will delete all associated data including exchanges, queues, and RabbitMQ virtual host.
// @Tags         users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        deleteAccountRequest  body  DeleteAccountRequest  true  "Account deletion request payload with password confirmation"
// @Success      200 {object}  GenericResponse "Account deleted successfully"
// @Failure      400 {object} echo.HTTPError     "Bad request, missing required fields"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid password or expired session token"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/users/delete-account [delete]
func DeleteAccountHandler(c echo.Context) error {
	logger := c.Logger()

	rmqClient, err := rabbitmq.NewClient(rabbitmq.RabbitMQConfig{})
	if err != nil {
		logger.Error("Failed to initialize RabbitMQ client:", err)
		return echo.ErrInternalServerError
	}

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	var req DeleteAccountRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid delete account request payload:", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid request payload, please ensure it is well-formed and has content-type application/json header",
		}
	}

	if req.Password == "" {
		logger.Error("Password is required for account deletion.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "password field is required for account deletion confirmation",
		}
	}

	newCrypto := crypto.NewCrypto()
	if err := newCrypto.VerifyPassword(req.Password, user.Password); err != nil {
		logger.Error("Password verification failed for account deletion.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Password is incorrect, please check your password",
		}
	}

	tx := db.Conn.Begin()
	if tx.Error != nil {
		logger.Errorf("Transaction begin failed: %v", tx.Error)
		return echo.ErrInternalServerError
	}

	if err := tx.Unscoped().Where("user_id = ?", user.ID).Delete(&models.Session{}).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to delete user sessions: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Unscoped().Where("user_id = ?", user.ID).Delete(&models.APIKey{}).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to delete user API keys: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Unscoped().Where("user_id = ?", user.ID).Delete(&models.Exchange{}).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to delete user exchanges: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Unscoped().Delete(&user).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to delete user account: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.DeleteUser(user.AccountID); err != nil {
		tx.Rollback()
		logger.Errorf("Failed to delete RabbitMQ user: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.DeleteVhost(user.AccountID); err != nil {
		tx.Rollback()
		logger.Errorf("Failed to delete RabbitMQ vhost: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		logger.Errorf("Transaction commit failed: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("User account deleted successfully: %s", user.Email)
	return c.JSON(http.StatusOK, GenericResponse{
		Message: "Account deleted successfully",
	})
}
