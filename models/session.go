// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"gorm.io/gorm"
)

type Session struct {
	ID                 uint    `gorm:"primaryKey"`
	Token              string  `gorm:"size:255;not null;uniqueIndex"`
	IPAddress          *string `gorm:"size:255;default:null"`
	IPAddressEncrypted *[]byte `gorm:"size:255;default:null"`
	IPAddressPseudonym *[]byte `gorm:"size:255;default:null"`
	UserAgent          *string `gorm:"size:255;default:null"`
	UserAgentEncrypted *[]byte `gorm:"size:255;default:null"`
	UserAgentPseudonym *[]byte `gorm:"size:255;default:null"`
	LastUsedAt         *time.Time
	ExpiresAt          *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DeletedAt          gorm.DeletedAt `gorm:"index"`
	UserID             uint
	User               User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

func init() {
	AllModels = append(AllModels, &Session{})
}
