// SPDX-License-Identifier: GPL-3.0-only

package db

import (
	"os"
	"qdroid-server/commons"
	"qdroid-server/models"
	"strings"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func InitDB() {
	var err error
	dbDialect := strings.ToLower(commons.GetEnv("DB_DIALECT"))
	dbPath := commons.GetEnv("DB_PATH")
	if dbPath == "" {
		dbPath = "qdroid.db"
	}
	var dialector gorm.Dialector
	var dbInfo string

	switch dbDialect {
	case "postgres":
		dsn := commons.GetEnv("POSTGRES_DSN")
		if dsn == "" {
			commons.Logger.Error("POSTGRES_DSN environment variable is required for postgres dialect. Example: postgres://user:password@localhost:5432/qdroid")
			os.Exit(1)
		}
		commons.Logger.Debug("Connecting to PostgreSQL database")
		dialector = postgres.Open(dsn)
		dbInfo = "PostgreSQL database (DSN hidden)"
	case "mysql":
		dsn := commons.GetEnv("MYSQL_DSN")
		if dsn == "" {
			commons.Logger.Error("MYSQL_DSN environment variable is required for mysql dialect. Example: user:password@tcp(localhost:3306)/qdroid?charset=utf8mb4&parseTime=True&loc=Local")
			os.Exit(1)
		}
		commons.Logger.Debug("Connecting to MySQL database")
		dialector = mysql.Open(dsn)
		dbInfo = "MySQL database (DSN hidden)"
	default:
		commons.Logger.Debug("Connecting to SQLite database at", dbPath)
		dialector = sqlite.Open(dbPath)
		dbDialect = "sqlite"
		dbInfo = dbPath
	}

	var logLevel logger.LogLevel
	switch commons.Logger.Level() {
	case 1:
		logLevel = logger.Info
	case 2:
		logLevel = logger.Silent
	case 3:
		logLevel = logger.Warn
	case 4:
		logLevel = logger.Error
	default:
		logLevel = logger.Silent
	}

	DB, err = gorm.Open(dialector, &gorm.Config{
		Logger: logger.New(
			commons.Logger,
			logger.Config{
				SlowThreshold: 200 * 1e6,
				LogLevel:      logLevel,
				Colorful:      true,
			},
		),
	})
	if err != nil {
		commons.Logger.Error("Failed to connect to database:", err)
		os.Exit(1)
	}
	commons.Logger.Infof("Database connection established. %s %s, %s %s",
		"dialect:", dbDialect,
		"database:", dbInfo,
	)
}

func MigrateDB() {
	commons.Logger.Info("Running database migrations")
	err := DB.AutoMigrate(models.AllModels...)
	if err != nil {
		commons.Logger.Error("Database migration failed:", err)
		os.Exit(1)
	}
	commons.Logger.Info("Database migration completed")
}
