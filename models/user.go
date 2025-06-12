// SPDX-License-Identifier: GPL-3.0-only

package models

var AllModels []any

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
}

func init() {
	AllModels = append(AllModels, &User{})
}
