package testutil

import (
	"os"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// SetupTestDB creates a PostgreSQL test database connection with clean state
func SetupTestDB(t *testing.T, models ...interface{}) *gorm.DB {
	// Use DATABASE_URL if set (for CI), otherwise use local development defaults
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		// Local development default (matches docker compose)
		dsn = "host=localhost user=bifrost password=bifrost123 dbname=bifrost port=5432 sslmode=disable"
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Skipf("Failed to connect to test database (PostgreSQL may not be running): %v", err)
	}

	// Auto-migrate provided models first to ensure tables exist
	if len(models) > 0 {
		if err := db.AutoMigrate(models...); err != nil {
			t.Fatalf("Failed to migrate test database: %v", err)
		}
	}

	// Clean all tables after migration
	CleanDatabase(db)

	return db
}

// CleanDatabase truncates all tables to ensure clean test state
func CleanDatabase(db *gorm.DB) {
	// Clean up existing data only if tables exist
	tables := []string{"log_entries", "sessions", "users"}
	
	for _, table := range tables {
		// Check if table exists before truncating
		var exists bool
		db.Raw("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = ?)", table).Scan(&exists)
		if exists {
			db.Exec("TRUNCATE TABLE " + table + " CASCADE")
		}
	}
}
