// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"gorm.io/gorm"
)

type Exchange struct {
	ID          uint    `gorm:"primaryKey"`
	ExchangeID  string  `gorm:"size:255;not null;uniqueIndex"`
	Label       string  `gorm:"size:255;not null;uniqueIndex:idx_user_label"`
	Description *string `gorm:"type:text;default:null"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
	UserID      uint           `gorm:"uniqueIndex:idx_user_label"`
	User        User           `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

func init() {
	AllModels = append(AllModels, &Exchange{})
}
