// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"gorm.io/gorm"
)

var AllModels []any

type User struct {
	ID          uint    `gorm:"primaryKey"`
	Email       string  `gorm:"not null;uniqueIndex"`
	Password    string  `gorm:"not null"`
	PhoneNumber *string `gorm:"default:null"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func init() {
	AllModels = append(AllModels, &User{})
}
