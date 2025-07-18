// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"gorm.io/gorm"
)

type APIKey struct {
	ID          uint    `gorm:"primaryKey"`
	KeyID       string  `gorm:"size:255;not null;uniqueIndex"`
	HashedKey   string  `gorm:"size:255;not null;uniqueIndex"`
	Name        string  `gorm:"size:255;not null;uniqueIndex:idx_user_name"`
	Description *string `gorm:"type:text;default:null"`
	LastUsedAt  *time.Time
	ExpiresAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
	UserID      uint           `gorm:"uniqueIndex:idx_user_name"`
	User        User           `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

func init() {
	AllModels = append(AllModels, &APIKey{})
}
