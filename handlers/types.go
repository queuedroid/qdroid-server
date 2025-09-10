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
	// Optional full name
	FullName *string `json:"full_name" example:"John Doe"`
}

// swagger:model AuthResponse
type AuthResponse struct {
	// Authentication session token
	// This token is used for subsequent authenticated requests.
	// It should be stored securely by the client.
	// Should be used in the Authorization header as a Bearer token.
	SessionToken string `json:"session_token" example:"sample_session_token"`
	// Message indicating successful operation
	Message string `json:"message" example:"Operation successful"`
}

// swagger:model LoginRequest
type LoginRequest struct {
	// User's email address
	Email string `json:"email" example:"user@example.com"`
	// User's password
	Password string `json:"password" example:"MySecretPassword@123"`
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
	// Full name of the user
	FullName *string `json:"full_name" example:"John Doe"`
	// Whether the user's email is verified
	IsEmailVerified bool `json:"is_email_verified" example:"true"`
	// User's subscription plan
	Subscription string `json:"subscription" example:"FREE"`
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

// swagger:model QueueDetails
type QueueDetails struct {
	// Name of the queue
	Name string `json:"name"`
	// Number of messages in the queue
	// This is the number of messages that are currently in the queue waiting to be consumed.
	// It can be used to monitor the load on the queue.
	Messages int `json:"messages"`
	// Number of devices connected to the queue
	// This is the number of consumers that are currently consuming messages from this queue.
	// It can be used to monitor the load on the queue.
	Consumers int `json:"consumers"`
	// Current state of the queue
	// This indicates whether the queue is running, idle, or in an error state.
	// It can be used to monitor the health of the queue.
	// Example values: "running", "idle", "error"
	State string `json:"state"`
}

// swagger:model QueueListResponse
type QueueListResponse struct {
	// List of queues
	Data []QueueDetails `json:"data"`
	// Pagination details
	Pagination PaginationDetails `json:"pagination"`
	// Message indicating successful retrieval
	Message string `json:"message" example:"Queues retrieved successfully"`
}

// swagger:model EventLogDetails
type EventLogDetails struct {
	// Event ID
	EID string `json:"eid" example:"550e8400-e29b-41d4-a716-446655440000"`
	// Event category
	Category *string `json:"category" example:"MESSAGE"`
	// Event status
	Status *string `json:"status" example:"QUEUED"`
	// Exchange ID associated with the event
	ExchangeID *string `json:"exchange_id" example:"ex_jkdfkjdfkdfjkd"`
	// Queue name
	QueueName *string `json:"queue_name" example:"exch_jkdfkjdfkdfjkd_237_62401"`
	// Queue ID
	QueueID *string `json:"queue_id" example:"exch_jkdfkjdfkdfjkd.237.62401"`
	// Event description
	Description *string `json:"description" example:"Message sent successfully"`
	// Recipient phone number or email
	To *string `json:"to" example:"+2371234567890"`
	// Carrier used for the message
	Carrier *string `json:"carrier" example:"MTN"`
	// Timestamp of when the event was created
	CreatedAt string `json:"created_at" example:"2023-10-01T12:00:00Z"`
	// Timestamp of when the event was last updated
	UpdatedAt string `json:"updated_at" example:"2023-10-01T12:00:00Z"`
}

// swagger:model EventLogListResponse
type EventLogListResponse struct {
	// List of event logs
	Data []EventLogDetails `json:"data"`
	// Pagination details
	Pagination PaginationDetails `json:"pagination"`
	// Message indicating successful retrieval
	Message string `json:"message" example:"Event logs retrieved successfully"`
}

// swagger:model EventLogSummaryResponse
type EventLogSummaryResponse struct {
	Data    EventLogSummaryData `json:"data"`
	Message string              `json:"message" example:"Event logs summary retrieved successfully"`
}

// swagger:model EventLogSummaryData
type EventLogSummaryData struct {
	TotalCount   int64 `json:"total_count" example:"150"`
	TotalQueued  int64 `json:"total_queued" example:"130"`
	TotalFailed  int64 `json:"total_failed" example:"20"`
	TotalPending int64 `json:"total_pending" example:"0"`
}

// swagger:model ExchangeConnectionResponse
type ExchangeConnectionResponse struct {
	// Virtual host (user's account ID)
	VirtualHost string `json:"virtual_host" example:"acc_1234567890"`
	// Username for AMQP connection (user's account ID)
	Username string `json:"username" example:"acc_1234567890"`
	// Password for AMQP connection (user's account token)
	Password string `json:"password" example:"sample_account_token"`
	// Exchange ID
	Exchange string `json:"exchange" example:"ex_jkdfkjdfkdfjkd"`
	// Full AMQP URL for connection
	AMQPURL string `json:"amqp_url" example:"amqp://acc_1234567890:sample_account_token@localhost:5672/acc_1234567890"`
	// Host for AMQP connection
	Host string `json:"host" example:"localhost"`
	// Port for AMQP connection
	Port string `json:"port" example:"5672"`
	// Protocol for AMQP connection
	Protocol string `json:"protocol" example:"AMQP"`
	// Message indicating successful retrieval
	Message string `json:"message" example:"Exchange connection details retrieved successfully"`
}

// swagger:model QueueConnectionResponse
type QueueConnectionResponse struct {
	// Virtual host (user's account ID)
	VirtualHost string `json:"virtual_host" example:"acc_1234567890"`
	// Username for AMQP connection (user's account ID)
	Username string `json:"username" example:"acc_1234567890"`
	// Password for AMQP connection (user's account token)
	Password string `json:"password" example:"sample_account_token"`
	// Exchange ID
	Exchange string `json:"exchange" example:"ex_jkdfkjdfkdfjkd"`
	// Full AMQP URL for connection
	AMQPURL string `json:"amqp_url" example:"amqp://acc_1234567890:sample_account_token@localhost:5672/acc_1234567890"`
	// Host for AMQP connection
	Host string `json:"host" example:"localhost"`
	// Port for AMQP connection
	Port string `json:"port" example:"5672"`
	// Protocol for AMQP connection
	Protocol string `json:"protocol" example:"AMQP"`
	// Binding key or routing key for queue operations
	BindingKey string `json:"binding_key" example:"ex_jkdfkjdfkdfjkd.237.62401"`
	// Message indicating successful retrieval
	Message string `json:"message" example:"Queue connection details retrieved successfully"`
}

// swagger:model CreateAPIKeyRequest
type CreateAPIKeyRequest struct {
	// Name of the API key
	Name string `json:"name" example:"My API Key"`
	// Description of the API key
	Description *string `json:"description" example:"This key is used for accessing the QDroid API."`
	// Expiration date for the API key (optional)
	ExpiresAt *string `json:"expires_at" example:"2024-12-31"`
}

// swagger:model CreateAPIKeyResponse
type CreateAPIKeyResponse struct {
	// API key created
	APIKey string `json:"api_key" example:"ak_jkdfkjdfkdfjkdlklklkllklklklklklklklklklklkl"`
	// Key ID of the created API key
	KeyID string `json:"key_id" example:"ak_jkdfkjdfkdfjkd"`
	// Name of the API key
	Name string `json:"name" example:"My API Key"`
	// Description of the API key
	Description *string `json:"description" example:"This key is used for accessing the QDroid API."`
	// Timestamp of when the API key was created
	CreatedAt string `json:"created_at" example:"2023-10-01T12:00:00Z"`
	// Expiration date for the API key
	ExpiresAt *string `json:"expires_at" example:"2024-12-31"`
	// Message indicating successful creation
	Message string `json:"message" example:"API key created successfully"`
}

// swagger:model APIKeyDetails
type APIKeyDetails struct {
	// Key ID of the created API key
	KeyID string `json:"key_id" example:"ak_jkdfkjdfkdfjkd"`
	// Name of the API key
	Name string `json:"name" example:"My API Key"`
	// Description of the API key
	Description *string `json:"description" example:"This key is used for accessing the QDroid API."`
	// Timestamp of when the API key was created
	CreatedAt string `json:"created_at" example:"2023-10-01T12:00:00Z"`
	// Last used timestamp of the API key
	LastUsedAt *string `json:"last_used_at" example:"2023-10-01T12:00:00Z"`
	// Expiration date for the API key
	ExpiresAt *string `json:"expires_at" example:"2024-12-31"`
}

// swagger:model APIKeyListResponse
type APIKeyListResponse struct {
	// List of API keys
	Data []APIKeyDetails `json:"data"`
	// Pagination details
	Pagination PaginationDetails `json:"pagination"`
	// Message indicating successful retrieval
	Message string `json:"message" example:"API keys retrieved successfully"`
}

// swagger:model DeleteAccountRequest
type DeleteAccountRequest struct {
	// User's password
	// required: true
	Password string `json:"password" example:"MySecretPassword@123"`
}

// swagger:model ChangePasswordRequest
type ChangePasswordRequest struct {
	// Current password
	// required: true
	CurrentPassword string `json:"current_password" example:"MySecretPassword@123"`
	// New password
	// required: true
	NewPassword string `json:"new_password" example:"MyNewPassword@456"`
}

// swagger:model VerifyEmailRequest
type VerifyEmailRequest struct {
	// Email verification token
	// required: true
	Token string `json:"token" example:"evt_a1b2c3d4e5f6789"`
}

// swagger:model PlanDetails
type PlanDetails struct {
	// Plan ID
	ID uint `json:"id" example:"1"`
	// Plan name
	Name string `json:"name" example:"FREE"`
	// Plan price in cents
	Price uint `json:"price" example:"0"`
	// Currency for the plan price
	Currency string `json:"currency" example:"USD"`
	// Duration of the plan in days
	DurationInDays *uint `json:"duration_in_days" example:"30"`
	// Maximum number of projects allowed
	MaxProjects *uint `json:"max_projects" example:"5"`
	// Maximum messages per month allowed
	MaxMessagesPerMonth *uint `json:"max_messages_per_month" example:"1000"`
	// Maximum API keys allowed
	MaxAPIKeys *uint `json:"max_api_keys" example:"3"`
}

// swagger:model GetSubscriptionResponse
type GetSubscriptionResponse struct {
	// Message indicating successful operation
	Message string `json:"message" example:"Subscription details retrieved successfully"`
	// Subscription ID
	ID uint `json:"id" example:"1"`
	// Subscription status
	Status string `json:"status" example:"ACTIVE"`
	// Whether auto-renewal is enabled
	AutoRenew bool `json:"auto_renew" example:"true"`
	// Date when subscription started
	StartedAt string `json:"started_at" example:"2025-01-01T00:00:00Z"`
	// Date when subscription expires (null for unlimited plans)
	ExpiresAt *string `json:"expires_at" example:"2025-02-01T00:00:00Z"`
	// Days remaining until expiration (null for unlimited plans)
	DaysRemaining *int `json:"days_remaining" example:"22"`
	// Plan details
	Plan PlanDetails `json:"plan"`
	// Date when subscription was created
	CreatedAt string `json:"created_at" example:"2025-01-01T00:00:00Z"`
	// Date when subscription was last updated
	UpdatedAt string `json:"updated_at" example:"2025-01-01T00:00:00Z"`
}

// swagger:model UsageItem
type UsageItem struct {
	// Current usage count
	Current int `json:"current" example:"3"`
	// Maximum allowed (null means unlimited)
	Limit *uint `json:"limit" example:"5"`
	// Usage percentage (0-100, null if unlimited)
	Percentage *float64 `json:"percentage" example:"60.0"`
}

// swagger:model UsageDetails
type UsageDetails struct {
	// Projects usage
	Projects UsageItem `json:"projects"`
	// API keys usage
	APIKeys UsageItem `json:"api_keys"`
	// Messages sent this month
	MessagesThisMonth UsageItem `json:"messages_this_month"`
}

// swagger:model GetSubscriptionSummaryResponse
type GetSubscriptionSummaryResponse struct {
	// Message indicating successful operation
	Message string `json:"message" example:"Subscription summary retrieved successfully"`
	// Plan name
	PlanName string `json:"plan_name" example:"FREE"`
	// Subscription status
	Status string `json:"status" example:"ACTIVE"`
	// Whether auto-renewal is enabled
	AutoRenew bool `json:"auto_renew" example:"true"`
	// Days remaining until expiration (null for unlimited plans)
	DaysRemaining *int `json:"days_remaining" example:"22"`
	// Whether subscription is expiring within 7 days
	IsExpiringSoon bool `json:"is_expiring_soon" example:"false"`
	// Current usage details
	Usage UsageDetails `json:"usage"`
	// List of actions available to the user
	AvailableActions []string `json:"available_actions" example:"[\"create_project\", \"create_api_key\", \"send_message\"]"`
}

// swagger:model PlanPricing
type PlanPricing struct {
	// Monthly price in cents/smallest currency unit
	Monthly uint `json:"monthly" example:"999"`
	// Yearly price in cents/smallest currency unit
	Yearly uint `json:"yearly" example:"9999"`
	// Currency code
	Currency string `json:"currency" example:"USD"`
}

// swagger:model PlanOption
type PlanOption struct {
	// Plan ID
	ID uint `json:"id" example:"1"`
	// Plan name
	Name string `json:"name" example:"PLUS"`
	// Plan pricing information
	Pricing PlanPricing `json:"pricing"`
	// Whether this is the recommended plan
	Recommended bool `json:"recommended" example:"true"`
	// List of plan features
	Features []string `json:"features" example:"[\"Unlimited projects\", \"Priority support\", \"Advanced analytics\"]"`
	// Discount percentage for yearly plans
	Discount uint `json:"discount" example:"10"`
}

// swagger:model GetPlansResponse
type GetPlansResponse struct {
	// Operation success message
	Message string `json:"message" example:"Plans retrieved successfully"`
	// List of available plans
	Plans []PlanOption `json:"plans"`
}
