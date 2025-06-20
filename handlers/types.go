// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"time"
)

// swagger:model SignupRequest
type SignupRequest struct {
	// User's password
	// required: true
	Password string `json:"password" example:"MySecretPassword@123"`
	// User's email address
	// required: true
	Email string `json:"email" example:"user@example.com"`
	// Optional phone number
	PhoneNumber string `json:"phone_number" example:"+2371234567890"`
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

type GetOneAPIKeyResponse struct {
	Token      string     `json:"token,omitempty" example:"sample_api_key_token"`
	Label      *string    `json:"label,omitempty" example:"My API Key"`
	Seen       *bool      `json:"seen,omitempty" example:"false"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}
