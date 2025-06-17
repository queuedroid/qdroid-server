// SPDX-License-Identifier: GPL-3.0-only

package handlers

type SignupRequest struct {
	Password    string `json:"password"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
