// SPDX-License-Identifier: GPL-3.0-only

package migrations

import (
	"fmt"
	"qdroid-server/crypto"
	"qdroid-server/models"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func List() []*gormigrate.Migration {
	return []*gormigrate.Migration{
		{
			ID: "001_encrypt_users",
			Migrate: func(tx *gorm.DB) error {
				newCrypto := crypto.NewCrypto()

				var users []models.User
				if err := tx.Select("id", "email", "country_code", "full_name").
					Find(&users).Error; err != nil {
					return fmt.Errorf("failed to fetch users: %w", err)
				}

				for i := range users {
					updates := map[string]any{}

					if users[i].Email != "" {
						encEmail, err := newCrypto.EncryptData([]byte(users[i].Email), "AES-GCM")
						if err != nil {
							return fmt.Errorf("encrypt email: %w", err)
						}
						updates["email_encrypted"] = encEmail

						emailPseudo, err := newCrypto.HashData([]byte(users[i].Email), "HMAC-SHA-256")
						if err != nil {
							return fmt.Errorf("pseudonym email: %w", err)
						}
						updates["email_pseudonym"] = emailPseudo
					}

					if users[i].CountryCode != "" {
						encCC, err := newCrypto.EncryptData([]byte(users[i].CountryCode), "AES-GCM")
						if err != nil {
							return fmt.Errorf("encrypt country code: %w", err)
						}
						updates["country_code_encrypted"] = encCC
					}

					if users[i].FullName != nil && *users[i].FullName != "" {
						encFN, err := newCrypto.EncryptData([]byte(*users[i].FullName), "AES-GCM")
						if err != nil {
							return fmt.Errorf("encrypt full name: %w", err)
						}
						updates["full_name_encrypted"] = encFN
					}

					if len(updates) > 0 {
						if err := tx.Model(&users[i]).Updates(updates).Error; err != nil {
							return fmt.Errorf("update user %d: %w", users[i].ID, err)
						}
					}
				}
				return nil
			},
			Rollback: func(tx *gorm.DB) error { return nil },
		},
		{
			ID: "002_encrypt_sessions",
			Migrate: func(tx *gorm.DB) error {
				newCrypto := crypto.NewCrypto()

				var sessions []models.Session
				if err := tx.Select("id", "user_id", "ip_address", "user_agent").
					Find(&sessions).Error; err != nil {
					return fmt.Errorf("failed to fetch sessions: %w", err)
				}

				for i := range sessions {
					updates := map[string]any{}

					if sessions[i].IPAddress != nil && *sessions[i].IPAddress != "" {
						encIP, err := newCrypto.EncryptData([]byte(*sessions[i].IPAddress), "AES-GCM")
						if err != nil {
							return fmt.Errorf("encrypt ip: %w", err)
						}
						updates["ip_address_encrypted"] = encIP

						ipPseudo, err := newCrypto.HashData([]byte(*sessions[i].IPAddress), "HMAC-SHA-256")
						if err != nil {
							return fmt.Errorf("pseudonym ip: %w", err)
						}
						updates["ip_address_pseudonym"] = ipPseudo
					}

					if sessions[i].UserAgent != nil && *sessions[i].UserAgent != "" {
						encUA, err := newCrypto.EncryptData([]byte(*sessions[i].UserAgent), "AES-GCM")
						if err != nil {
							return fmt.Errorf("encrypt user agent: %w", err)
						}
						updates["user_agent_encrypted"] = encUA

						uaPseudo, err := newCrypto.HashData([]byte(*sessions[i].UserAgent), "HMAC-SHA-256")
						if err != nil {
							return fmt.Errorf("pseudonym user agent: %w", err)
						}
						updates["user_agent_pseudonym"] = uaPseudo
					}

					if len(updates) > 0 {
						if err := tx.Model(&sessions[i]).Updates(updates).Error; err != nil {
							return fmt.Errorf("update session %d: %w", sessions[i].ID, err)
						}
					}
				}
				return nil
			},
			Rollback: func(tx *gorm.DB) error { return nil },
		},
		{
			ID: "003_create_stats",
			Migrate: func(tx *gorm.DB) error {
				var users []models.User

				if err := tx.Select("country_code, created_at").
					Find(&users).Error; err != nil {
					return fmt.Errorf("failed to fetch users for stats: %w", err)
				}

				for _, user := range users {
					stat := models.Stats{
						Type:        models.StatsTypeSignup,
						CountryCode: &user.CountryCode,
						CreatedAt:   user.CreatedAt,
					}
					if err := tx.Create(&stat).Error; err != nil {
						return fmt.Errorf("failed to create stat: %w", err)
					}
				}

				return nil
			},
			Rollback: func(tx *gorm.DB) error { return nil },
		},
	}
}
