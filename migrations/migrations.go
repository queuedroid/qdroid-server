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
		// {
		// 	ID: "001_encrypt_users",
		// 	Migrate: func(tx *gorm.DB) error {
		// 		newCrypto := crypto.NewCrypto()

		// 		var users []models.User
		// 		if err := tx.Select("id", "email", "country_code", "full_name").
		// 			Find(&users).Error; err != nil {
		// 			return fmt.Errorf("failed to fetch users: %w", err)
		// 		}

		// 		for i := range users {
		// 			updates := map[string]any{}

		// 			if users[i].Email != "" {
		// 				encEmail, err := newCrypto.EncryptData([]byte(users[i].Email), "AES-GCM")
		// 				if err != nil {
		// 					return fmt.Errorf("encrypt email: %w", err)
		// 				}
		// 				updates["email_encrypted"] = encEmail

		// 				emailPseudo, err := newCrypto.HashData([]byte(users[i].Email), "HMAC-SHA-256")
		// 				if err != nil {
		// 					return fmt.Errorf("pseudonym email: %w", err)
		// 				}
		// 				updates["email_pseudonym"] = emailPseudo
		// 			}

		// 			if users[i].CountryCode != "" {
		// 				encCC, err := newCrypto.EncryptData([]byte(users[i].CountryCode), "AES-GCM")
		// 				if err != nil {
		// 					return fmt.Errorf("encrypt country code: %w", err)
		// 				}
		// 				updates["country_code_encrypted"] = encCC
		// 			}

		// 			if users[i].FullName != nil && *users[i].FullName != "" {
		// 				encFN, err := newCrypto.EncryptData([]byte(*users[i].FullName), "AES-GCM")
		// 				if err != nil {
		// 					return fmt.Errorf("encrypt full name: %w", err)
		// 				}
		// 				updates["full_name_encrypted"] = encFN
		// 			}

		// 			if len(updates) > 0 {
		// 				if err := tx.Model(&users[i]).Updates(updates).Error; err != nil {
		// 					return fmt.Errorf("update user %d: %w", users[i].ID, err)
		// 				}
		// 			}
		// 		}
		// 		return nil
		// 	},
		// 	Rollback: func(tx *gorm.DB) error { return nil },
		// },
		// {
		// 	ID: "002_encrypt_sessions",
		// 	Migrate: func(tx *gorm.DB) error {
		// 		newCrypto := crypto.NewCrypto()

		// 		var sessions []models.Session
		// 		if err := tx.Select("id", "user_id", "ip_address", "user_agent").
		// 			Find(&sessions).Error; err != nil {
		// 			return fmt.Errorf("failed to fetch sessions: %w", err)
		// 		}

		// 		for i := range sessions {
		// 			updates := map[string]any{}

		// 			if sessions[i].IPAddress != nil && *sessions[i].IPAddress != "" {
		// 				encIP, err := newCrypto.EncryptData([]byte(*sessions[i].IPAddress), "AES-GCM")
		// 				if err != nil {
		// 					return fmt.Errorf("encrypt ip: %w", err)
		// 				}
		// 				updates["ip_address_encrypted"] = encIP

		// 				ipPseudo, err := newCrypto.HashData([]byte(*sessions[i].IPAddress), "HMAC-SHA-256")
		// 				if err != nil {
		// 					return fmt.Errorf("pseudonym ip: %w", err)
		// 				}
		// 				updates["ip_address_pseudonym"] = ipPseudo
		// 			}

		// 			if sessions[i].UserAgent != nil && *sessions[i].UserAgent != "" {
		// 				encUA, err := newCrypto.EncryptData([]byte(*sessions[i].UserAgent), "AES-GCM")
		// 				if err != nil {
		// 					return fmt.Errorf("encrypt user agent: %w", err)
		// 				}
		// 				updates["user_agent_encrypted"] = encUA

		// 				uaPseudo, err := newCrypto.HashData([]byte(*sessions[i].UserAgent), "HMAC-SHA-256")
		// 				if err != nil {
		// 					return fmt.Errorf("pseudonym user agent: %w", err)
		// 				}
		// 				updates["user_agent_pseudonym"] = uaPseudo
		// 			}

		// 			if len(updates) > 0 {
		// 				if err := tx.Model(&sessions[i]).Updates(updates).Error; err != nil {
		// 					return fmt.Errorf("update session %d: %w", sessions[i].ID, err)
		// 				}
		// 			}
		// 		}
		// 		return nil
		// 	},
		// 	Rollback: func(tx *gorm.DB) error { return nil },
		// },
		// {
		// 	ID: "003_create_stats",
		// 	Migrate: func(tx *gorm.DB) error {
		// 		var users []models.User

		// 		if err := tx.Select("country_code, created_at").
		// 			Find(&users).Error; err != nil {
		// 			return fmt.Errorf("failed to fetch users for stats: %w", err)
		// 		}

		// 		for _, user := range users {
		// 			stat := models.Stats{
		// 				Type:        models.StatsTypeSignup,
		// 				CountryCode: &user.CountryCode,
		// 				CreatedAt:   user.CreatedAt,
		// 			}
		// 			if err := tx.Create(&stat).Error; err != nil {
		// 				return fmt.Errorf("failed to create stat: %w", err)
		// 			}
		// 		}

		// 		return nil
		// 	},
		// 	Rollback: func(tx *gorm.DB) error { return nil },
		// },
		{
			ID: "004_delete_unused_columns",
			Migrate: func(tx *gorm.DB) error {
				if err := tx.Migrator().DropColumn(&models.User{}, "email"); err != nil {
					return fmt.Errorf("failed to drop email column: %w", err)
				}
				if err := tx.Migrator().DropColumn(&models.User{}, "country_code"); err != nil {
					return fmt.Errorf("failed to drop country_code column: %w", err)
				}
				if err := tx.Migrator().DropColumn(&models.User{}, "phone_number"); err != nil {
					return fmt.Errorf("failed to drop phone_number column: %w", err)
				}
				if err := tx.Migrator().DropColumn(&models.User{}, "full_name"); err != nil {
					return fmt.Errorf("failed to drop full_name column: %w", err)
				}
				if err := tx.Migrator().DropColumn(&models.Session{}, "ip_address"); err != nil {
					return fmt.Errorf("failed to drop ip_address column: %w", err)
				}
				if err := tx.Migrator().DropColumn(&models.Session{}, "user_agent"); err != nil {
					return fmt.Errorf("failed to drop user_agent column: %w", err)
				}
				return nil
			},
			Rollback: func(tx *gorm.DB) error { return nil },
		},
		{
			ID: "005_add_free_plus_plans",
			Migrate: func(tx *gorm.DB) error {
				freePlanMaxProjects := uint(1)
				freePlanMaxMessagesPerMonth := uint(100)
				plusDurationInDays := uint(30)
				plans := []models.Plan{
					{
						MaxProjects:         &freePlanMaxProjects,
						MaxMessagesPerMonth: &freePlanMaxMessagesPerMonth,
					},
					{
						Name:           models.PlusPlan,
						Price:          20,
						Currency:       "USD",
						DurationInDays: &plusDurationInDays,
					},
				}

				for _, plan := range plans {
					if err := tx.Create(&plan).Error; err != nil {
						return fmt.Errorf("failed to create plan %s: %w", plan.Name, err)
					}
				}

				return nil
			},
			Rollback: func(tx *gorm.DB) error { return nil },
		},
		{
			ID: "006_subscribe_existing_users_to_free_plan",
			Migrate: func(tx *gorm.DB) error {
				var users []models.User
				if err := tx.Find(&users).Error; err != nil {
					return fmt.Errorf("failed to fetch users: %w", err)
				}

				var freePlan models.Plan
				if err := tx.Where("name = ?", models.FreePlan).First(&freePlan).Error; err != nil {
					return fmt.Errorf("failed to fetch free plan: %w", err)
				}

				for _, user := range users {
					var subscription models.Subscription
					if err := tx.Where("user_id = ? AND status = ?", user.ID, models.ActiveSubscription).
						Assign(models.Subscription{
							UserID:    user.ID,
							PlanID:    freePlan.ID,
							Status:    models.ActiveSubscription,
							StartedAt: user.CreatedAt,
						}).FirstOrCreate(&subscription).Error; err != nil {
						return fmt.Errorf("failed to create subscription for user %d: %w", user.ID, err)
					}
				}
				return nil
			},
			Rollback: func(tx *gorm.DB) error { return nil },
		},
		{
			ID: "007_set_max_api_keys_for_plans",
			Migrate: func(tx *gorm.DB) error {
				freeMaxAPIKeys := uint(1)
				if err := tx.Model(&models.Plan{}).
					Where("name = ?", models.FreePlan).
					Update("max_api_keys", freeMaxAPIKeys).Error; err != nil {
					return fmt.Errorf("failed to update free plan max API keys: %w", err)
				}

				return nil
			},
			Rollback: func(tx *gorm.DB) error { return nil },
		},
		{
			ID: "008_add_subscription_id",
			Migrate: func(tx *gorm.DB) error {
				if err := tx.Exec("DROP INDEX IF EXISTS idx_subscriptions_subscription_id ON subscriptions").Error; err != nil {
					return fmt.Errorf("failed to drop subscription_id index: %w", err)
				}

				if err := tx.Exec("ALTER TABLE subscriptions MODIFY COLUMN subscription_id VARCHAR(64) NULL").Error; err != nil {
					return fmt.Errorf("failed to remove NOT NULL constraint from subscription_id: %w", err)
				}

				var subscriptions []models.Subscription
				if err := tx.Find(&subscriptions).Error; err != nil {
					return fmt.Errorf("failed to fetch existing subscriptions: %w", err)
				}

				for _, subscription := range subscriptions {
					subID, err := crypto.GenerateRandomString("sub_", 16, "hex")
					if err != nil {
						return fmt.Errorf("failed to generate subscription ID: %w", err)
					}

					if err := tx.Model(&subscription).Update("subscription_id", subID).Error; err != nil {
						return fmt.Errorf("failed to update subscription %d with subscription_id: %w", subscription.ID, err)
					}
				}

				if err := tx.Exec("ALTER TABLE subscriptions MODIFY COLUMN subscription_id VARCHAR(64) NOT NULL").Error; err != nil {
					return fmt.Errorf("failed to add NOT NULL constraint to subscription_id: %w", err)
				}

				if err := tx.Exec("CREATE UNIQUE INDEX idx_subscriptions_subscription_id ON subscriptions(subscription_id)").Error; err != nil {
					return fmt.Errorf("failed to create unique index on subscription_id: %w", err)
				}

				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				if err := tx.Exec("DROP INDEX IF EXISTS idx_subscriptions_subscription_id ON subscriptions").Error; err != nil {
					return fmt.Errorf("failed to drop subscription_id index: %w", err)
				}

				if err := tx.Migrator().DropColumn(&models.Subscription{}, "subscription_id"); err != nil {
					return fmt.Errorf("failed to drop subscription_id column: %w", err)
				}

				return nil
			},
		},
	}
}
