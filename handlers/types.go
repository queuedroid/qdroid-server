// SPDX-License-Identifier: GPL-3.0-only

package handlers

// swagger:model SignupRequest
type SignupRequest struct {
	// User's password
	// required: true
	Password string `json:"password" example:"MySecretPassword@123"`
	// User's email address
	// required: true
	Email string `json:"email" example:"user@example.com"`
	// User's ISO 3166-1 alpha-2 country code
	CountryCode string `json:"country_code" example:"CM"`
	// Optional phone number
	PhoneNumber *string `json:"phone_number" example:"+2371234567890"`
	// Optional full name
	FullName *string `json:"full_name" example:"John Doe"`
}

// swagger:model SignupResponse
type SignupResponse struct {
	// Message indicating successful signup
	Message string `json:"message" example:"Signup successful"`
}

// swagger:model LoginRequest
type LoginRequest struct {
	// User's email address
	Email string `json:"email" example:"user@example.com"`
	// User's password
	Password string `json:"password" example:"MySecretPassword@123"`
}

// swagger:model LoginResponse
type LoginResponse struct {
	// Authentication session token
	// This token is used for subsequent authenticated requests.
	// It should be stored securely by the client.
	// Should be used in the Authorization header as a Bearer token.
	SessionToken string `json:"session_token" example:"sample_session_token"`
	// Message indicating successful login
	Message string `json:"message" example:"Login successful"`
}

// swagger:model CreateExchangeRequest
type CreateExchangeRequest struct {
	// Label for the exchange
	Label string `json:"label" example:"OTP Messages"`
	// Description of the exchange
	Description *string `json:"description" example:"This exchange handles OTP messages."`
}

// swagger:model CreateExchangeResponse
type CreateExchangeResponse struct {
	// ID of the created exchange
	ExchangeID string `json:"exchange_id" example:"ex_jkdfkjdfkdfjkd"`
	// Label of the created exchange
	Label string `json:"label" example:"OTP Messages"`
	// Description of the created exchange
	Description *string `json:"description" example:"This exchange handles OTP messages."`
	// Timestamp of when the exchange was created
	CreatedAt string `json:"created_at" example:"2023-10-01T12:00:00Z"`
	// Timestamp of when the exchange was last updated
	UpdatedAt string `json:"updated_at" example:"2023-10-01T12:00:00Z"`
	// Message indicating successful creation
	Message string `json:"message" example:"Exchange created successfully"`
}

// swagger:model GetUserResponse
type GetUserResponse struct {
	// Unique identifier for the user
	AccountID string `json:"account_id" example:"acc_1234567890"`
	// Authentication token for the user's account
	AccountToken string `json:"account_token" example:"sample_account_token"`
	// Email address associated with the user's account
	Email string `json:"email" example:"user@example.com"`
	// Phone number associated with the user's account
	PhoneNumber *string `json:"phone_number" example:"+2371234567890"`
	// Full name of the user
	FullName *string `json:"full_name" example:"John Doe"`
	// Message indicating successful retrieval
	Message string `json:"message" example:"User retrieved successfully"`
}

// swagger:model UpdateExchangeRequest
type UpdateExchangeRequest struct {
	// New label for the exchange
	Label string `json:"label" example:"New OTP Messages"`
	// New description for the exchange
	Description *string `json:"description" example:"This exchange handles new OTP messages."`
}

// swagger:model PaginationDetails
type PaginationDetails struct {
	// Current page number
	Page int `json:"page"`
	// Page size
	PageSize int `json:"page_size"`
	// Total number of items
	Total int64 `json:"total"`
	// Total number of pages
	TotalPages int `json:"total_pages"`
}

// swagger:model ExchangeDetails
type ExchangeDetails struct {
	// ID of the exchange
	ExchangeID string `json:"exchange_id" example:"ex_jkdfkjdfkdfjkd"`
	// Label of the exchange
	Label string `json:"label" example:"OTP Messages"`
	// Description of the exchange
	Description *string `json:"description" example:"This exchange handles OTP messages."`
	// Timestamp of when the exchange was created
	CreatedAt string `json:"created_at" example:"2023-10-01T12:00:00Z"`
	// Timestamp of when the exchange was last updated
	UpdatedAt string `json:"updated_at" example:"2023-10-01T12:00:00Z"`
}

// swagger:model ExchangeListResponse
type ExchangeListResponse struct {
	// List of exchanges
	Data []ExchangeDetails `json:"data"`
	// Pagination details
	Pagination PaginationDetails `json:"pagination"`
	// Message indicating successful retrieval
	Message string `json:"message" example:"Exchanges retrieved successfully"`
}

// swagger:model CreateBindQueueRequest
type CreateBindQueueRequest struct {
	// Country code (e.g. 237)
	CountryCode string `json:"country_code" example:"237"`
	// Mobile Country Code (MCC) (e.g. 624)
	MCC string `json:"mcc" example:"624"`
	// Mobile Network Code (MNC) (e.g. 01)
	MNC string `json:"mnc" example:"01"`
}

// swagger:model CreateBindQueueResponse
type CreateBindQueueResponse struct {
	// Message indicating successful creation and binding
	Message string `json:"message" example:"Queue created and bound to exchange successfully"`
	// Name of the created queue
	Queue string `json:"queue" example:"exch_jkdfkjdfkdfjkd_237_11223"`
	// Exchange ID the queue was bound to
	Exchange string `json:"exchange" example:"exch_jkdfkjdfkdfjkd"`
	// Vhost used for the operation
	Vhost string `json:"vhost" example:"acc_1234567890"`
	// Routing key used for binding
	RoutingKey string `json:"routing_key" example:"exch_jkdfkjdfkdfjkd.237.62401"`
}

// swagger:model GenericResponse
type GenericResponse struct {
	// Message indicating the result of the operation
	Message string `json:"message"`
}

// swagger:model SendMessageRequest
type SendMessageRequest struct {
	// The exchange ID to send the message to
	ExchangeID string `json:"exchange_id" example:"ex_jkdfkjdfkdfjkd"`
	// The message content to be sent
	Content string `json:"content" example:"Hello, World!"`
	// The phone number to send the message to
	PhoneNumber string `json:"phone_number" example:"+2371234567890"`
	// The queue ID to use for sending the message
	QueueID *string `json:"queue_id" example:"exch_jkdfkjdfkdfjkd.237.62401"`
}

// swagger:model BulkSendMessageRequest
type BulkSendMessageRequest struct {
	// List of messages to send
	Messages []SendMessageRequest `json:"messages"`
}

// swagger:model BulkSendMessageResponse
type BulkSendMessageResponse struct {
	// Message indicating that bulk processing has started
	Message string `json:"message" example:"Bulk message processing started. Check your logs for more details."`
	// Number of messages accepted for processing
	Count int `json:"count" example:"5"`
}
