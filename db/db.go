package db

import (
	"os"
	"qdroid-server/commons"
	"strings"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	var err error
	dbEngine := strings.ToLower(os.Getenv("DB_ENGINE"))
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "qdroid.db"
	}
	var dialector gorm.Dialector
	var dbInfo string

	switch dbEngine {
	case "postgres":
		dsn := os.Getenv("POSTGRES_DSN")
		if dsn == "" {
			commons.Logger.Error("POSTGRES_DSN environment variable is required for postgres engine. Example: postgres://user:password@localhost:5432/qdroid")
			os.Exit(1)
		}
		commons.Logger.Debug("Connecting to PostgreSQL database")
		dialector = postgres.Open(dsn)
		dbInfo = "PostgreSQL database (DSN hidden)"
	case "mysql":
		dsn := os.Getenv("MYSQL_DSN")
		if dsn == "" {
			commons.Logger.Error("MYSQL_DSN environment variable is required for mysql engine. Example: user:password@tcp(localhost:3306)/qdroid?charset=utf8mb4&parseTime=True&loc=Local")
			os.Exit(1)
		}
		commons.Logger.Debug("Connecting to MySQL database")
		dialector = mysql.Open(dsn)
		dbInfo = "MySQL database (DSN hidden)"
	default:
		commons.Logger.Debug("Connecting to SQLite database at", dbPath)
		dialector = sqlite.Open(dbPath)
		dbEngine = "sqlite"
		dbInfo = dbPath
	}

	DB, err = gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		commons.Logger.Error("failed to connect database:", err)
		os.Exit(1)
	}
	commons.Logger.Info("Database connection established",
		"engine:", dbEngine,
		"database:", dbInfo,
	)
}
