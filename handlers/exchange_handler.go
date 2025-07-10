// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/models"
	"qdroid-server/rabbitmq"
	"strings"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// CreateExchangeHandler godoc
// @Summary      Create a new exchange
// @Description  Creates a new exchange for the user.
// @Tags         exchanges
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        createExchangeRequest  body  CreateExchangeRequest  true  "Create exchange request payload"
// @Success      201 {object} CreateExchangeResponse "Exchange created successfully"
// @Failure      400 {object} echo.HTTPError     "Bad request, missing required fields"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      409 {object} echo.HTTPError     "Duplicate exchange label"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/exchanges/ [post]
func CreateExchangeHandler(c echo.Context) error {
	logger := c.Logger()

	rmqClient, err := rabbitmq.NewClient(rabbitmq.RabbitMQConfig{})
	if err != nil {
		logger.Error("Failed to initialize RabbitMQ client:", err)
		return echo.ErrInternalServerError
	}

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	var req CreateExchangeRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid create exchange request payload:", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid request payload, please ensure it is well-formed and has content-type application/json header",
		}
	}

	if req.Label == "" {
		logger.Error("Label is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "label field is required",
		}
	}

	count := db.Conn.Where("label = ? AND user_id = ?", req.Label, session.UserID).First(&models.Exchange{}).RowsAffected
	if count > 0 {
		logger.Errorf("Duplicate exchange label detected.")
		return &echo.HTTPError{
			Code:    http.StatusConflict,
			Message: "You already have an exchange with this label. Please try another one.",
		}
	}

	exchangeID, err := crypto.GenerateRandomString("exch_", 16, "hex")
	if err != nil {
		logger.Errorf("Failed to generate exchange ID: %v", err)
		return echo.ErrInternalServerError
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

	exchange := models.Exchange{
		ExchangeID:  exchangeID,
		Label:       req.Label,
		Description: req.Description,
		UserID:      user.ID,
	}

	tx := db.Conn.Begin()
	if tx.Error != nil {
		logger.Errorf("Transaction begin failed: %v", tx.Error)
		return echo.ErrInternalServerError
	}

	if err := tx.Create(&exchange).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create exchange: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.CreateExchange(user.AccountID, exchangeID, "topic", true); err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create exchange in RabbitMQ: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		logger.Errorf("Transaction commit failed: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("Exchange created successfully.")
	return c.JSON(http.StatusCreated, CreateExchangeResponse{
		Message:     "Successfully created exchange",
		ExchangeID:  exchange.ExchangeID,
		Label:       exchange.Label,
		Description: exchange.Description,
		CreatedAt:   exchange.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   exchange.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// UpdateExchangeHandler godoc
// @Summary      Update an exchange
// @Description  Update an existing exchange..
// @Tags         exchanges
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        exchange_id   path    string  true  "Exchange ID"
// @Param        updateExchangeRequest  body  UpdateExchangeRequest  true  "Update exchange request payload"
// @Success      200 {object} CreateExchangeResponse "Exchange updated successfully"
// @Failure      400 {object} echo.HTTPError     "Bad request, missing required fields"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      409 {object} echo.HTTPError     "Duplicate exchange label detected"
// @Failure      404 {object} echo.HTTPError     "Exchange not found"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/exchanges/{exchange_id} [put]
func UpdateExchangeHandler(c echo.Context) error {
	logger := c.Logger()
	exchangeID := c.Param("exchange_id")

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	var req UpdateExchangeRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid update exchange request payload:", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid request payload, please ensure it is well-formed and has content-type application/json header",
		}
	}

	if req.Label == "" {
		logger.Error("Label is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "label field is required",
		}
	}

	exchange := models.Exchange{}
	if err := db.Conn.Where("exchange_id = ? AND user_id = ?", exchangeID, session.UserID).First(&exchange).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("Exchange not found.")
			return &echo.HTTPError{
				Code:    http.StatusNotFound,
				Message: "Exchange not found",
			}
		}

		logger.Errorf("Failed to find exchange: %v", err)
		return echo.ErrInternalServerError
	}

	if req.Label != "" && req.Label != exchange.Label {
		count := db.Conn.Where("label = ? AND user_id = ?", req.Label, session.UserID).First(&models.Exchange{}).RowsAffected
		if count > 0 {
			logger.Errorf("Duplicate exchange label detected.")
			return &echo.HTTPError{
				Code:    http.StatusConflict,
				Message: "You already have an exchange with this label. Please try another one.",
			}
		}
		exchange.Label = req.Label
	}
	if req.Description != nil {
		exchange.Description = req.Description
	}

	if err := db.Conn.Save(&exchange).Error; err != nil {
		logger.Errorf("Failed to update exchange: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("Exchange updated successfully.")
	return c.JSON(http.StatusOK, CreateExchangeResponse{
		Message:     "Successfully updated exchange",
		ExchangeID:  exchange.ExchangeID,
		Label:       exchange.Label,
		Description: exchange.Description,
		CreatedAt:   exchange.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   exchange.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// DeleteExchangeHandler godoc
// @Summary      Delete an exchange
// @Description  Deletes an existing exchange.
// @Tags         exchanges
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        exchange_id   path    string  true  "Exchange ID"
// @Success      200 {object} GenericResponse    "Exchange deleted successfully"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      404 {object} echo.HTTPError     "Exchange not found"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/exchanges/{exchange_id} [delete]
func DeleteExchangeHandler(c echo.Context) error {
	logger := c.Logger()
	exchangeID := c.Param("exchange_id")

	rmqClient, err := rabbitmq.NewClient(rabbitmq.RabbitMQConfig{})
	if err != nil {
		logger.Error("Failed to initialize RabbitMQ client:", err)
		return echo.ErrInternalServerError
	}

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	exchange := models.Exchange{}
	if err := db.Conn.Where("exchange_id = ? AND user_id = ?", exchangeID, session.UserID).First(&exchange).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("Exchange not found.")
			return &echo.HTTPError{
				Code:    http.StatusNotFound,
				Message: "Exchange not found",
			}
		}

		logger.Errorf("Failed to find exchange: %v", err)
		return echo.ErrInternalServerError
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

	tx := db.Conn.Begin()
	if tx.Error != nil {
		logger.Errorf("Transaction begin failed: %v", tx.Error)
		return echo.ErrInternalServerError
	}

	if err := tx.Delete(&exchange).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to delete exchange: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.DeleteExchange(user.AccountID, exchangeID); err != nil {
		tx.Rollback()
		logger.Errorf("Failed to delete exchange in RabbitMQ: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		logger.Errorf("Transaction commit failed: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("Exchange deleted successfully.")
	return c.JSON(http.StatusOK, GenericResponse{
		Message: "Successfully deleted exchange",
	})
}

// GetExchangeHandler godoc
// @Summary      Get a single exchange
// @Description  Retrieves a single exchange by its ID for the authenticated user.
// @Tags         exchanges
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        exchange_id   path    string  true  "Exchange ID"
// @Success      200 {object} ExchangeDetails "Exchange details retrieved successfully"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      404 {object} echo.HTTPError     "Exchange not found"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/exchanges/{exchange_id} [get]
func GetExchangeHandler(c echo.Context) error {
	logger := c.Logger()
	exchangeID := c.Param("exchange_id")

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	exchange := models.Exchange{}
	if err := db.Conn.Where("exchange_id = ? AND user_id = ?", exchangeID, session.UserID).First(&exchange).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("Exchange not found.")
			return &echo.HTTPError{
				Code:    http.StatusNotFound,
				Message: "Exchange not found",
			}
		}
		logger.Errorf("Failed to find exchange: %v", err)
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, ExchangeDetails{
		ExchangeID:  exchange.ExchangeID,
		Label:       exchange.Label,
		Description: exchange.Description,
		CreatedAt:   exchange.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   exchange.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// GetAllExchangesHandler godoc
// @Summary      Get all exchanges (paginated)
// @Description  Retrieves all exchanges for the authenticated user, paginated.
// @Tags         exchanges
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        page     query   int  false  "Page number (default 1)"
// @Param        page_size query  int  false  "Page size (default 10, max 100)"
// @Success      200 {object} ExchangeListResponse "Paginated list of exchanges"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/exchanges/ [get]
func GetAllExchangesHandler(c echo.Context) error {
	logger := c.Logger()

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
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
	var exchanges []models.Exchange
	db.Conn.Model(&models.Exchange{}).Where("user_id = ?", session.UserID).Count(&total)
	db.Conn.Where("user_id = ?", session.UserID).
		Order("created_at desc").
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		Find(&exchanges)

	var data []ExchangeDetails
	for _, ex := range exchanges {
		data = append(data, ExchangeDetails{
			ExchangeID:  ex.ExchangeID,
			Label:       ex.Label,
			Description: ex.Description,
			CreatedAt:   ex.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:   ex.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	return c.JSON(http.StatusOK, ExchangeListResponse{
		Data: data,
		Pagination: PaginationDetails{
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		},
		Message: "Exchanges retrieved successfully",
	})
}

// CreateAndBindQueueHandler godoc
// @Summary      Create a queue and bind it to an exchange
// @Description  Creates a new queue binds it to the specified exchange.
// @Tags         exchanges
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        exchange_id   path    string  true  "Exchange ID"
// @Param        createBindQueueRequest  body  CreateBindQueueRequest  true  "Create and bind queue request payload. You can get MCC and MNC from https://www.mcc-mnc.com/"
// @Success      201 {object} CreateBindQueueResponse "Queue created and bound successfully"
// @Failure      400 {object} echo.HTTPError
// @Failure      401 {object} echo.HTTPError
// @Failure      404 {object} echo.HTTPError
// @Failure      500 {object} echo.HTTPError
// @Router       /v1/exchanges/{exchange_id}/queues [post]
func CreateAndBindQueueHandler(c echo.Context) error {
	logger := c.Logger()
	exchangeID := c.Param("exchange_id")

	rmqClient, err := rabbitmq.NewClient(rabbitmq.RabbitMQConfig{})
	if err != nil {
		logger.Error("Failed to initialize RabbitMQ client:", err)
		return echo.ErrInternalServerError
	}

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	var req CreateBindQueueRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid create/bind queue request payload:", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid request payload, please ensure it is well-formed and has content-type application/json header",
		}
	}

	if req.CountryCode == "" {
		logger.Error("CountryCode is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "country_code field is required",
		}
	}
	if req.MCC == "" {
		logger.Error("MCC is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "mcc field is required",
		}
	}
	if req.MNC == "" {
		logger.Error("MNC is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "mnc field is required",
		}
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

	exchange := models.Exchange{}
	if err := db.Conn.Where("exchange_id = ? AND user_id = ?", exchangeID, session.UserID).First(&exchange).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("Exchange not found for binding.")
			return &echo.HTTPError{
				Code:    http.StatusNotFound,
				Message: "Exchange not found",
			}
		}
		logger.Errorf("Failed to find exchange: %v", err)
		return echo.ErrInternalServerError
	}

	// You can get MCC and MNC from https://www.mcc-mnc.com/
	plmnID := fmt.Sprintf("%s%s", req.MCC, req.MNC)
	// Generate routing key: {exchange_id}.{country_code}.{plmn_id}
	routingKey := fmt.Sprintf("%s.%s.%s", exchangeID, req.CountryCode, plmnID)
	queueName := strings.ReplaceAll(routingKey, ".", "_")
	durable := true
	autoDelete := false
	arguments := make(map[string]interface{})
	bindArguments := make(map[string]interface{})

	if err := rmqClient.CreateQueue(user.AccountID, queueName, durable, autoDelete, arguments); err != nil {
		logger.Errorf("Failed to create queue in RabbitMQ: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.BindQueue(user.AccountID, queueName, exchangeID, routingKey, bindArguments); err != nil {
		logger.Errorf("Failed to bind queue to exchange in RabbitMQ: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("Queue created and bound successfully.")
	return c.JSON(http.StatusCreated, CreateBindQueueResponse{
		Message:    "Queue created and bound to exchange successfully",
		Queue:      queueName,
		Exchange:   exchangeID,
		Vhost:      user.AccountID,
		RoutingKey: routingKey,
	})
}

// GetExchangeQueuesHandler godoc
// @Summary      Get queues for an exchange (paginated)
// @Description  Retrieves all queues bound to a specific exchange, paginated.
// @Tags         exchanges
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        exchange_id   path    string  true  "Exchange ID"
// @Param        page     query   int  false  "Page number (default 1)"
// @Param        page_size query  int  false  "Page size (default 10, max 100)"
// @Success      200 {object} QueueListResponse "Paginated list of queues"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      404 {object} echo.HTTPError     "Exchange not found"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/exchanges/{exchange_id}/queues [get]
func GetExchangeQueuesHandler(c echo.Context) error {
	logger := c.Logger()
	exchangeID := c.Param("exchange_id")

	rmqClient, err := rabbitmq.NewClient(rabbitmq.RabbitMQConfig{})
	if err != nil {
		logger.Error("Failed to initialize RabbitMQ client:", err)
		return echo.ErrInternalServerError
	}

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	exchange := models.Exchange{}
	if err := db.Conn.Where("exchange_id = ? AND user_id = ?", exchangeID, session.UserID).First(&exchange).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error("Exchange not found.")
			return &echo.HTTPError{
				Code:    http.StatusNotFound,
				Message: "Exchange not found",
			}
		}
		logger.Errorf("Failed to find exchange: %v", err)
		return echo.ErrInternalServerError
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

	queues, paginationMeta, err := rmqClient.GetQueuesForExchange(user.AccountID, exchangeID, page, pageSize)
	if err != nil {
		logger.Errorf("Failed to fetch queues from RabbitMQ: %v", err)
		return echo.ErrInternalServerError
	}

	var data []QueueDetails
	for _, queue := range queues {
		queueDetail := QueueDetails{
			Name:      queue["name"].(string),
			State:     queue["state"].(string),
			Messages:  int(queue["messages"].(float64)),
			Consumers: int(queue["consumers"].(float64)),
		}
		data = append(data, queueDetail)
	}

	pagination := PaginationDetails{
		Page:       int(paginationMeta["page"].(int)),
		PageSize:   int(paginationMeta["page_size"].(int)),
		Total:      paginationMeta["total"].(int64),
		TotalPages: int(paginationMeta["total_pages"].(int)),
	}

	return c.JSON(http.StatusOK, QueueListResponse{
		Data:       data,
		Pagination: pagination,
		Message:    "Queues retrieved successfully",
	})
}
