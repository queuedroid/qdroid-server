// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"gorm.io/gorm"
)

type PasswordReset struct {
	ID        uint   `gorm:"primaryKey"`
	Token     string `gorm:"size:255;not null;uniqueIndex"`
	IsUsed    bool   `gorm:"not null;default:false"`
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
	UserID    uint
	User      User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

func init() {
	AllModels = append(AllModels, &PasswordReset{})
}
