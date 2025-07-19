package auth

import (
	"time"
)

// User represents a simple user record
type User struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Sub       string    `json:"sub" gorm:"uniqueIndex;not null"` // OIDC subject identifier
	Email     string    `json:"email"`                           // User email
	Name      string    `json:"name"`                            // User display name
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Session represents a user session
type Session struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	UserID    uint      `json:"user_id" gorm:"index"`
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