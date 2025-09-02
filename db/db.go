// SPDX-License-Identifier: GPL-3.0-only

package db

import (
	"fmt"
	"os"
	"qdroid-server/commons"
	"qdroid-server/migrations"
	"qdroid-server/models"
	"strings"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var Conn *gorm.DB

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
		user := commons.GetEnv("DB_USER")
		pass := commons.GetEnv("DB_PASSWORD")
		host := commons.GetEnv("DB_HOST", "localhost")
		port := commons.GetEnv("DB_PORT", "5432")
		dbname := commons.GetEnv("DB_NAME")
		sslmode := commons.GetEnv("DB_SSLMODE", "disable")
		if user == "" || pass == "" || dbname == "" {
			commons.Logger.Error("DB_USER, DB_PASSWORD, and DB_NAME environment variables are required for postgres dialect.")
			os.Exit(1)
		}
		dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", user, pass, host, port, dbname, sslmode)
		commons.Logger.Debug("Connecting to PostgreSQL database")
		dialector = postgres.Open(dsn)
		dbInfo = fmt.Sprint("postgres://", user, ":", "****", "@", host, ":", port, "/", dbname, "?sslmode=", sslmode)
	case "mysql":
		user := commons.GetEnv("DB_USER")
		pass := commons.GetEnv("DB_PASSWORD")
		host := commons.GetEnv("DB_HOST", "localhost")
		port := commons.GetEnv("DB_PORT", "3306")
		dbname := commons.GetEnv("DB_NAME")
		loc, _ := time.LoadLocation("UTC")
		params := fmt.Sprintf("charset=utf8mb4&parseTime=True&loc=%s", loc)
		if user == "" || pass == "" || dbname == "" {
			commons.Logger.Error("DB_USER, DB_PASSWORD, and DB_NAME environment variables are required for mysql dialect.")
			os.Exit(1)
		}

		rootDsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/?%s", user, pass, host, port, params)
		rootDB, err := gorm.Open(mysql.Open(rootDsn), &gorm.Config{})
		if err != nil {
			commons.Logger.Errorf("Failed to connect to MySQL server for DB creation: %v", err)
			os.Exit(1)
		}
		createDBSQL := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;", dbname)
		if err := rootDB.Exec(createDBSQL).Error; err != nil {
			commons.Logger.Errorf("Failed to create database '%s': %v", dbname, err)
			os.Exit(1)
		}
		sqlDB, _ := rootDB.DB()
		sqlDB.Close()

		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?%s", user, pass, host, port, dbname, params)
		commons.Logger.Debug("Connecting to MySQL database")
		dialector = mysql.Open(dsn)
		dbInfo = fmt.Sprint("mysql://", user, ":", "****", "@tcp(", host, ":", port, ")/", dbname, "?charset=utf8mb4&parseTime=True&loc=", loc)
	default:
		commons.Logger.Debug("Connecting to SQLite database at", dbPath)
		dialector = sqlite.Open(dbPath)
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

	Conn, err = gorm.Open(dialector, &gorm.Config{
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
		commons.Logger.Errorf("Failed to connect to database: %v", err)
		os.Exit(1)
	}
	commons.Logger.Infof("Database connection established at %s", dbInfo)
}

func MigrateDB() {
	commons.Logger.Info("Running database migrations")
	if err := Conn.AutoMigrate(models.AllModels...); err != nil {
		commons.Logger.Errorf("Schema migration failed: %v", err)
		os.Exit(1)
	}

	m := gormigrate.New(Conn, gormigrate.DefaultOptions, migrations.List())
	if err := m.Migrate(); err != nil {
		commons.Logger.Errorf("Data migrations failed: %v", err)
		os.Exit(1)
	}
	commons.Logger.Info("Database migration completed")
}
