package testutil

import (
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// SetupTestDB creates a PostgreSQL test database connection with clean state
func SetupTestDB(t *testing.T, models ...interface{}) *gorm.DB {
	// Use the same PostgreSQL connection as in docker-compose
	dsn := "host=localhost user=bifrost password=bifrost123 dbname=bifrost port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Skipf("Failed to connect to test database (PostgreSQL may not be running): %v", err)
	}

	// Clean all tables
	CleanDatabase(db)

	// Auto-migrate provided models
	if len(models) > 0 {
		if err := db.AutoMigrate(models...); err != nil {
			t.Fatalf("Failed to migrate test database: %v", err)
		}
	}

	return db
}

// CleanDatabase truncates all tables to ensure clean test state
func CleanDatabase(db *gorm.DB) {
	// Clean up existing data (ignore errors if tables don't exist)
	db.Exec("TRUNCATE TABLE log_entries CASCADE")
	db.Exec("TRUNCATE TABLE sessions CASCADE")
	db.Exec("TRUNCATE TABLE users CASCADE")
}