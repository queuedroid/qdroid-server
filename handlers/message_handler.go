// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"qdroid-server/commons"
	"qdroid-server/db"
	"qdroid-server/models"
	"qdroid-server/rabbitmq"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/nyaruka/phonenumbers"
	"gorm.io/gorm"
)

// SendMessageHandler godoc
// @Summary      Send a single message
// @Description  Sends a single message to the specified exchange and phone number.
// @Tags         messages
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        sendMessageRequest  body  SendMessageRequest  true  "Send message request payload"
// @Success      200 {object} GenericResponse "Message processed successfully"
// @Failure      400 {object} echo.HTTPError     "Bad request, missing required fields or invalid phone number"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      404 {object} echo.HTTPError     "Exchange or queue not found"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/messages/send [post]
func SendMessageHandler(c echo.Context) error {
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

	var req SendMessageRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid send message request payload:", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid request payload, please ensure it is well-formed and has content-type application/json header",
		}
	}

	httpErr := processMessage(req, session, logger, rmqClient)

	if httpErr != nil {
		return httpErr
	}

	return c.JSON(http.StatusOK, GenericResponse{
		Message: "Message processed successfully. Check your logs for more details.",
	})
}

// SendBulkMessagesHandler godoc
// @Summary      Send multiple messages
// @Description  Sends multiple messages in bulk. Processing is done asynchronously.
// @Tags         messages
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        bulkSendMessageRequest  body  BulkSendMessageRequest  true  "Bulk send message request payload"
// @Success      202 {object} BulkSendMessageResponse "Bulk message processing started"
// @Failure      400 {object} echo.HTTPError     "Bad request, missing required fields or empty messages array"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/messages/bulk-send [post]
func SendBulkMessagesHandler(c echo.Context) error {
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

	var req BulkSendMessageRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid bulk send message request payload:", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid request payload, please ensure it is well-formed and has content-type application/json header",
		}
	}

	if len(req.Messages) == 0 {
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "messages field must be a non-empty array",
		}
	}

	for _, msg := range req.Messages {
		go processMessage(msg, session, logger, rmqClient)
	}

	return c.JSON(http.StatusAccepted, BulkSendMessageResponse{
		Message: "Bulk message processing started. Check your logs for more details.",
		Count:   len(req.Messages),
	})
}

func processMessage(req SendMessageRequest, session models.Session, logger echo.Logger, rmqClient *rabbitmq.Client) *echo.HTTPError {
	if req.ExchangeID == "" {
		logger.Error("Missing ExchangeID in message request.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "exchange_id field is required",
		}
	}
	if req.Content == "" {
		logger.Error("Missing Content in message request.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "content field is required",
		}
	}
	if req.PhoneNumber == "" {
		logger.Error("Missing PhoneNumber in message request.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "phone_number field is required",
		}
	}

	parsedNumber, err := phonenumbers.Parse(req.PhoneNumber, "")
	if err != nil {
		logger.Errorf("Failed to parse phone number '%s': %v", req.PhoneNumber, err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "phone_number field must be a valid E.164 phone number. Please ensure it starts with a '+' followed by the country code and national number.",
		}
	}
	if !phonenumbers.IsValidNumber(parsedNumber) {
		logger.Errorf("Invalid phone number format: %s", req.PhoneNumber)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "phone_number field must be a valid E.164 phone number. Please ensure it starts with a '+' followed by the country code and national number.",
		}
	}

	exchange := models.Exchange{}
	if err := db.Conn.Where("exchange_id = ? AND user_id = ?", req.ExchangeID, session.UserID).First(&exchange).Error; err != nil {
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

	var queueID string
	var carrierInfo *string
	logFailure := func(msg string) error {
		logger.Error(msg)
		_ = LogMessageEventFailureHandler(
			&req.ExchangeID,
			&req.PhoneNumber,
			session.UserID,
			&msg,
			nil,
			nil,
			carrierInfo,
		)
		return nil
	}

	if req.QueueID == nil || *req.QueueID == "" {
		region := phonenumbers.GetRegionCodeForNumber(parsedNumber)
		carrier, prefix, err := phonenumbers.GetCarrierWithPrefixForNumber(parsedNumber, "en")
		if err != nil {
			logFailure(fmt.Sprintf("Carrier lookup failed for phone number '%s': %v", req.PhoneNumber, err))
			return &echo.HTTPError{
				Code:    http.StatusBadRequest,
				Message: "Carrier information not found for phone number",
			}
		}
		if carrier == "" {
			logFailure("Carrier not found for phone number: " + req.PhoneNumber)
			return &echo.HTTPError{
				Code:    http.StatusBadRequest,
				Message: "Carrier information not found for phone number",
			}
		}
		if prefix == 0 {
			logFailure("Prefix not found for phone number: " + req.PhoneNumber)
			return &echo.HTTPError{
				Code:    http.StatusBadRequest,
				Message: "Prefix information not found for phone number",
			}
		}
		upperCarrier := strings.ToUpper(carrier)
		carrierInfo = &upperCarrier
		countryCode := phonenumbers.GetCountryCodeForRegion(region)
		mccmncList := commons.MCCMNCIndex.LookupByPrefix(fmt.Sprintf("%d", prefix))
		if len(mccmncList) == 0 {
			logFailure("MCCMNC not found for phone number: " + req.PhoneNumber)
			return &echo.HTTPError{
				Code:    http.StatusBadRequest,
				Message: "MCCMNC not found for phone number",
			}
		}
		mccmnc := mccmncList[0].MCCMNC
		queueID = fmt.Sprintf("%s.%d.%d", req.ExchangeID, countryCode, mccmnc)
	} else {
		queueID = *req.QueueID
	}

	queueName := strings.ReplaceAll(queueID, ".", "_")
	if !rmqClient.HasQueueBinding(user.AccountID, queueName, exchange.ExchangeID) {
		logFailure(fmt.Sprintf("Queue %s does not exist for exchange '%s'", queueName, exchange.Label))
		return &echo.HTTPError{
			Code:    http.StatusNotFound,
			Message: "Queue not found",
		}
	}

	if err := rmqClient.Publish(
		user.AccountID,
		exchange.ExchangeID,
		queueID,
		[]byte(req.Content),
		"",
	); err != nil {
		logger.Errorf("Failed to publish message to RabbitMQ: %v", err)
		return &echo.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to publish message to RabbitMQ",
		}
	}

	_ = LogMessageEventSuccessHandler(
		&req.ExchangeID,
		&req.PhoneNumber,
		session.UserID,
		&queueName,
		&queueID,
		carrierInfo,
	)

	logger.Info("Successfully queued message.")
	return nil
}
