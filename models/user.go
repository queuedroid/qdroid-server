package models

import (
	"qdroid-server/crypto"
)

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
}

func HashPassword(password string) string {
	return crypto.HashPassword(password)
}

func VerifyPassword(password, hash string) bool {
	return crypto.VerifyPassword(password, hash)
}
