// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"gorm.io/gorm"
)

type PlanName string

const (
	FreePlan PlanName = "FREE"
	PlusPlan PlanName = "PLUS"
)

type Plan struct {
	ID                  uint     `gorm:"primaryKey"`
	Name                PlanName `gorm:"size:255;not null;default:'FREE';uniqueIndex"`
	Price               uint     `gorm:"not null;default:0"`
	Currency            string   `gorm:"size:10;not null;default:'USD'"`
	DurationInDays      *uint    `gorm:"default:null"`
	MaxProjects         *uint    `gorm:"default:null"`
	MaxMessagesPerMonth *uint    `gorm:"default:null"`
	MaxAPIKeys          *uint    `gorm:"default:null"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DeletedAt           gorm.DeletedAt `gorm:"index"`
}

func init() {
	AllModels = append(AllModels, &Plan{})
}
