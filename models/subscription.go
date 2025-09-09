// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"gorm.io/gorm"
)

type SubscriptionStatus string

const (
	ActiveSubscription   SubscriptionStatus = "ACTIVE"
	InactiveSubscription SubscriptionStatus = "INACTIVE"
	CanceledSubscription SubscriptionStatus = "CANCELED"
)

type Subscription struct {
	ID        uint               `gorm:"primaryKey"`
	Status    SubscriptionStatus `gorm:"size:50;not null;default:'ACTIVE'"`
	AutoRenew bool               `gorm:"not null;default:true"`
	StartedAt time.Time
	ExpiresAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
	UserID    uint
	User      User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	PlanID    uint
	Plan      Plan `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

func init() {
	AllModels = append(AllModels, &Subscription{})
}
