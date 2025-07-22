package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID                     uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;"`
	Sub                    string         `json:"sub" gorm:"uniqueIndex;not null"` // OIDC subject identifier
	Email                  string         `json:"email" gorm:"index"`
	Name                   string         `json:"name"`
	MaxRequestsPerMinute   int            `json:"max_requests_per_minute" gorm:"default:60"` // Rate limit
	CreatedAt              time.Time      `json:"created_at"`
	UpdatedAt              time.Time      `json:"updated_at"`
	DeletedAt              gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// Session represents a user session
type Session struct {
	ID        string         `json:"id" gorm:"primary_key"`
	UserID    uuid.UUID      `json:"user_id" gorm:"type:uuid;not null;index"`
	User      User           `json:"user" gorm:"foreignKey:UserID"`
	IDToken   string         `json:"id_token"`
	ExpiresAt time.Time      `json:"expires_at" gorm:"index"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}