package logging

import (
	"time"

	"bifrost-gov/internal/models"
	"github.com/google/uuid"
)

// LogEntry represents a secure log entry with user context
type LogEntry struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID         *uuid.UUID `json:"user_id" gorm:"type:uuid;index"`       // Foreign key to users table
	User           *models.User `json:"user,omitempty" gorm:"foreignKey:UserID"`
	RequestID      string     `json:"request_id" gorm:"index"`              // Unique request identifier
	ModelProvider  string     `json:"model_provider"`                       // Which AI provider was used
	ModelName      string     `json:"model_name"`                           // Model name (e.g., gpt-4, claude-3)
	TokensUsed     int        `json:"tokens_used"`                          // Number of tokens consumed
	ResponseTimeMs int        `json:"response_time_ms"`                     // Response time in milliseconds
	StatusCode     int        `json:"status_code"`                          // HTTP status code
	ErrorMessage   string     `json:"error_message,omitempty"`              // Error message if request failed
	RequestType    string     `json:"request_type"`                         // Type: "chat", "completion", "embedding", etc.
	IPAddress      string     `json:"ip_address,omitempty"`                 // Client IP (optional)
	UserAgent      string     `json:"user_agent,omitempty"`                 // Client user agent (optional)
	CreatedAt      time.Time  `json:"created_at"`
}