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
	// Optional phone number
	PhoneNumber *string `json:"phone_number" example:"+2371234567890"`
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
	// Message indicating successful retrieval
	Message string `json:"message" example:"User retrieved successfully"`
}
