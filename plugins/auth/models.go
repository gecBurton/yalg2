package auth

import (
	"time"

	"github.com/google/uuid"
)

// User represents a simple user record
type User struct {
	ID                    uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Sub                   string    `json:"sub" gorm:"uniqueIndex;not null"`        // OIDC subject identifier
	Email                 string    `json:"email"`                                  // User email
	Name                  string    `json:"name"`                                   // User display name
	MaxRequestsPerMinute  int       `json:"max_requests_per_minute" gorm:"default:60"` // Rate limit: requests per minute
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// Session represents a user session
type Session struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;index"`
	User      *User     `json:"user,omitempty" gorm:"foreignKey:UserID"`
	IDToken   string    `json:"id_token"`
	ExpiresAt time.Time `json:"expires_at" gorm:"index"` // Index for efficient cleanup
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// OIDCConfig holds OIDC provider configuration
type OIDCConfig struct {
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
	DatabaseURL  string `json:"database_url"`
	RedirectURL  string `json:"redirect_url"`
}