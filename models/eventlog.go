// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type EventStatus string
type EventCategory string

const (
	Pending EventStatus = "PENDING"
	Queued  EventStatus = "QUEUED"
	Failed  EventStatus = "FAILED"
)

const (
	Message EventCategory = "MESSAGE"
	Payment EventCategory = "PAYMENT"
	Auth    EventCategory = "AUTH"
)

type EventLog struct {
	ID          uint           `gorm:"primaryKey"`
	EID         uuid.UUID      `gorm:"type:uuid;not null;"`
	Category    *EventCategory `gorm:"type:enum('MESSAGE','PAYMENT','AUTH');default:null"`
	Status      *EventStatus   `gorm:"type:enum('PENDING','QUEUED','FAILED');default:null"`
	ExchangeID  *string        `gorm:"size:255;default:null;"`
	QueueName   *string        `gorm:"size:255;default:null;"`
	QueueID     *string        `gorm:"size:255;default:null;"`
	Description *string        `gorm:"type:text;default:null;"`
	To          *string        `gorm:"size:255;default:null;"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
	UserID      uint
	User        User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

func (eventLog *EventLog) BeforeCreate(tx *gorm.DB) (err error) {
	eventLog.EID = uuid.New()
	return
}

func init() {
	AllModels = append(AllModels, &EventLog{})
}
