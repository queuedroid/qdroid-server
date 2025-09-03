// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"gorm.io/gorm"
)

type StatsType string

const (
	StatsTypeSignup StatsType = "SIGNUP"
)

type Stats struct {
	ID          uint      `gorm:"primaryKey"`
	Type        StatsType `gorm:"size:50;not null;index"`
	CountryCode *string   `gorm:"size:10;default:null;index"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func init() {
	AllModels = append(AllModels, &Stats{})
}
