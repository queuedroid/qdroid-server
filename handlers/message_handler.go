// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"qdroid-server/commons"
	"qdroid-server/db"
	"qdroid-server/middlewares"
	"qdroid-server/models"
	"qdroid-server/rabbitmq"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/nyaruka/phonenumbers"
	"gorm.io/gorm"

	amqp "github.com/rabbitmq/amqp091-go"
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

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
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

	conn, ch, err := rmqClient.CreateAMQPConnection(user.AccountID)
	if err != nil {
		logger.Errorf("Failed to create RabbitMQ connection: %v", err)
		return echo.ErrInternalServerError
	}

	defer func() {
		if ch != nil {
			logger.Debug("Closing RabbitMQ channel")
			ch.Close()
		}
		if conn != nil {
			logger.Debug("Closing RabbitMQ connection")
			conn.Close()
		}
	}()

	httpErr := processMessage(req, user, logger, rmqClient, conn, ch)

	if httpErr != nil {
		return httpErr
	}

	return c.JSON(http.StatusOK, GenericResponse{
		Message: "Message processed successfully. Check your logs for more details.",
	})
}

// SendBulkMessagesHandler godoc
// @Summary      Send multiple messages
// @Description  Sends multiple messages in bulk. Accepts JSON payload or CSV file upload. Processing is done asynchronously.
// @Tags         messages
// @Accept       json,multipart/form-data
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        bulkSendMessageRequest  body  BulkSendMessageRequest  false  "Bulk send message request payload (for JSON)"
// @Param        file  formData  file  false  "CSV file containing message data (for CSV upload)"
// @Success      202 {object} BulkSendMessageResponse "Bulk message processing started"
// @Failure      400 {object} echo.HTTPError     "Bad request, missing required fields or invalid data"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      413 {object} echo.HTTPError     "File too large (CSV only)"
// @Failure      415 {object} echo.HTTPError     "Unsupported media type, please use application/json or multipart/form-data"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/messages/bulk-send [post]
func SendBulkMessagesHandler(c echo.Context) error {
	logger := c.Logger()

	rmqClient, err := rabbitmq.NewClient(rabbitmq.RabbitMQConfig{})
	if err != nil {
		logger.Errorf("Failed to initialize RabbitMQ client: %v", err)
		return echo.ErrInternalServerError
	}

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Errorf("Failed to get authenticated user: %v", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	var messages []SendMessageRequest
	var messageCount int

	contentType := c.Request().Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/form-data") {
		messages, err = parseCSVFromRequest(c, logger, user.ID)
		if err != nil {
			return err
		}
		messageCount = len(messages)
	} else if strings.Contains(contentType, "application/json") {
		var req BulkSendMessageRequest
		if err := c.Bind(&req); err != nil {
			logger.Errorf("Invalid bulk send message request payload: %v", err)
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

		messages = req.Messages
		messageCount = len(messages)
	} else {
		logger.Errorf("Unsupported content type: %v", contentType)
		return &echo.HTTPError{
			Code:    http.StatusUnsupportedMediaType,
			Message: "Unsupported content type, please use application/json or multipart/form-data",
		}
	}

	go func() {
		conn, ch, err := rmqClient.CreateAMQPConnection(user.AccountID)
		if err != nil {
			logger.Errorf("Failed to create RabbitMQ connection: %v", err)
			return
		}

		defer func() {
			if ch != nil {
				logger.Debug("Closing RabbitMQ channel")
				ch.Close()
			}
			if conn != nil {
				logger.Debug("Closing RabbitMQ connection")
				conn.Close()
			}
		}()

		for _, msg := range messages {
			processMessage(msg, user, logger, rmqClient, conn, ch)
		}
	}()

	return c.JSON(http.StatusAccepted, BulkSendMessageResponse{
		Message: "Bulk message processing started. Check your logs for more details.",
		Count:   messageCount,
	})
}

func parseCSVFromRequest(c echo.Context, logger echo.Logger, userID uint) ([]SendMessageRequest, error) {
	file, err := c.FormFile("file")
	if err != nil {
		logger.Errorf("Failed to get uploaded file: %v", err)
		return nil, &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "No file uploaded or invalid file format",
		}
	}

	maxSize := int64(10 * 1024 * 1024)
	if file.Size > maxSize {
		logger.Errorf("Uploaded %s file with size %d exceeds maximum size of 10MB", file.Filename, file.Size)
		return nil, &echo.HTTPError{
			Code:    http.StatusRequestEntityTooLarge,
			Message: "File size exceeds maximum limit of 10MB",
		}
	}

	if !strings.HasSuffix(strings.ToLower(file.Filename), ".csv") {
		return nil, &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Only CSV files are allowed",
		}
	}

	src, err := file.Open()
	if err != nil {
		logger.Errorf("Failed to open uploaded file: %v", err)
		return nil, echo.ErrInternalServerError
	}
	defer src.Close()

	messages, err := parseCSVMessages(src, userID)
	if err != nil {
		logger.Errorf("Failed to parse CSV: %v", err)
		return nil, &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("Invalid CSV format: %v", err),
		}
	}

	if len(messages) == 0 {
		logger.Warn("No valid messages found in CSV file")
		return nil, &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "No valid messages found in CSV file",
		}
	}

	return messages, nil
}

func parseCSVMessages(reader io.Reader, userID uint) ([]SendMessageRequest, error) {
	csvReader := csv.NewReader(reader)
	csvReader.TrimLeadingSpace = true

	header, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	columnMap := make(map[string]int)
	requiredColumns := []string{"exchange_id", "phone_number", "content"}

	for i, col := range header {
		columnMap[strings.ToLower(strings.TrimSpace(col))] = i
	}

	for _, reqCol := range requiredColumns {
		if _, exists := columnMap[reqCol]; !exists {
			return nil, fmt.Errorf("missing required column: %s", reqCol)
		}
	}

	var messages []SendMessageRequest
	rowNum := 1

	for {
		row, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			errMsg := fmt.Sprintf("failed to read CSV row %d: %v", rowNum+1, err)
			_ = LogMessageEventFailureHandler(
				nil,
				nil,
				userID,
				&errMsg,
				nil,
				nil,
				nil,
			)
			rowNum++
			continue
		}

		if isEmptyRow(row) {
			rowNum++
			continue
		}

		msg, err := parseMessageFromRow(row, columnMap)
		if err != nil {
			errMsg := fmt.Sprintf("invalid CSV row %d: %v", rowNum+1, err)
			_ = LogMessageEventFailureHandler(
				nil,
				nil,
				userID,
				&errMsg,
				nil,
				nil,
				nil,
			)
			rowNum++
			continue
		}

		messages = append(messages, msg)
		rowNum++
	}

	return messages, nil
}

func isEmptyRow(row []string) bool {
	for _, cell := range row {
		if strings.TrimSpace(cell) != "" {
			return false
		}
	}
	return true
}

func parseMessageFromRow(row []string, columnMap map[string]int) (SendMessageRequest, error) {
	var msg SendMessageRequest

	if idx, exists := columnMap["exchange_id"]; exists && idx < len(row) {
		msg.ExchangeID = strings.TrimSpace(row[idx])
	}
	if msg.ExchangeID == "" {
		return msg, errors.New("exchange_id is required")
	}

	if idx, exists := columnMap["phone_number"]; exists && idx < len(row) {
		msg.PhoneNumber = strings.TrimSpace(row[idx])
	}
	if msg.PhoneNumber == "" {
		return msg, errors.New("phone_number is required")
	}

	if idx, exists := columnMap["content"]; exists && idx < len(row) {
		msg.Content = strings.TrimSpace(row[idx])
	}
	if msg.Content == "" {
		return msg, errors.New("content is required")
	}

	if idx, exists := columnMap["queue_id"]; exists && idx < len(row) {
		queueID := strings.TrimSpace(row[idx])
		if queueID != "" {
			msg.QueueID = &queueID
		}
	}

	return msg, nil
}

func processMessage(req SendMessageRequest, user *models.User, logger echo.Logger, rmqClient *rabbitmq.Client, conn *amqp.Connection, ch *amqp.Channel) *echo.HTTPError {
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
	if err := db.Conn.Where("exchange_id = ? AND user_id = ?", req.ExchangeID, user.ID).First(&exchange).Error; err != nil {
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

	var queueID string
	var carrierInfo *string
	logFailure := func(msg string) error {
		logger.Error(msg)
		_ = LogMessageEventFailureHandler(
			&req.ExchangeID,
			&req.PhoneNumber,
			user.ID,
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

	messagePayload := map[string]interface{}{
		"id":   rand.IntN(1000000000),
		"sid":  uuid.New().String(),
		"body": req.Content,
		"to":   req.PhoneNumber,
	}

	messageBytes, err := json.Marshal(messagePayload)
	if err != nil {
		logger.Errorf("Failed to marshal message payload: %v", err)
		return &echo.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create message payload",
		}
	}

	if err := rmqClient.Publish(
		user.AccountID,
		exchange.ExchangeID,
		queueID,
		messageBytes,
		"",
		conn,
		ch,
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
		user.ID,
		&queueName,
		&queueID,
		carrierInfo,
	)

	logger.Info("Successfully queued message.")
	return nil
}
