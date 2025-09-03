// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"gorm.io/gorm"
)

var AllModels []any

type User struct {
	ID                   uint    `gorm:"primaryKey"`
	AccountID            string  `gorm:"size:255;not null;uniqueIndex"`
	AccountToken         string  `gorm:"size:255;not null;index"`
	Email                string  `gorm:"size:255;not null;uniqueIndex"`
	EmailEncrypted       []byte  `gorm:"size:255;not null"`
	EmailPseudonym       []byte  `gorm:"size:255;not null"`
	Password             string  `gorm:"size:255;not null"`
	CountryCode          string  `gorm:"size:10;not null"`
	CountryCodeEncrypted []byte  `gorm:"size:255;not null"`
	PhoneNumber          *string `gorm:"size:255;default:null"`
	FullName             *string `gorm:"size:255;default:null"`
	FullNameEncrypted    *[]byte `gorm:"size:255;default:null"`
	CreatedAt            time.Time
	UpdatedAt            time.Time
	DeletedAt            gorm.DeletedAt `gorm:"index"`
}

func init() {
	AllModels = append(AllModels, &User{})
}
