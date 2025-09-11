// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"qdroid-server/crypto"

	"gorm.io/gorm"
)

type SubscriptionStatus string

const (
	ActiveSubscription   SubscriptionStatus = "ACTIVE"
	InactiveSubscription SubscriptionStatus = "INACTIVE"
	CanceledSubscription SubscriptionStatus = "CANCELED"
)

type Subscription struct {
	ID             uint               `gorm:"primaryKey"`
	SubscriptionID string             `gorm:"size:64"`
	Status         SubscriptionStatus `gorm:"size:50;not null;default:'ACTIVE'"`
	AutoRenew      bool               `gorm:"not null;default:true"`
	StartedAt      time.Time
	ExpiresAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`
	UserID         uint
	User           User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	PlanID         uint
	Plan           Plan `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

func (subscription *Subscription) BeforeCreate(tx *gorm.DB) (err error) {
	if subscription.SubscriptionID == "" {
		subscription.SubscriptionID, err = crypto.GenerateRandomString("sub_", 16, "hex")
		if err != nil {
			return err
		}
	}
	return
}

func init() {
	AllModels = append(AllModels, &Subscription{})
}
