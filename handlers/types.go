// SPDX-License-Identifier: GPL-3.0-only

package handlers

// swagger:model SignupRequest
type SignupRequest struct {
	// User's password
	// required: true
	Password string `json:"password"`
	// User's email address
	// required: true
	Email string `json:"email"`
	// Optional phone number
	PhoneNumber string `json:"phone_number"`
}

// swagger:model SignupResponse
type SignupResponse struct {
	// Signup successful message
	Message string `json:"message"`
}

// swagger:model LoginRequest
type LoginRequest struct {
	// User's email address
	Email string `json:"email"`
	// User's password
	Password string `json:"password"`
}
