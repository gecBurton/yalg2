package middleware

import (
	"encoding/json"
	"log"
	"strconv"

	"bifrost-gov/internal/database"

	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// AdminHandler handles admin-only endpoints
type AdminHandler struct {
	db *gorm.DB
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(db *gorm.DB) *AdminHandler {
	return &AdminHandler{
		db: db,
	}
}

// UserListResponse represents the paginated user list response
type UserListResponse struct {
	Users      []UserInfo `json:"users"`
	Page       int        `json:"page"`
	PageSize   int        `json:"page_size"`
	Total      int64      `json:"total"`
	TotalPages int        `json:"total_pages"`
}

// UserInfo represents user information for admin view
type UserInfo struct {
	ID                   string `json:"id"`
	Email                string `json:"email"`
	Name                 string `json:"name"`
	IsAdmin              bool   `json:"is_admin"`
	MaxRequestsPerMinute int    `json:"max_requests_per_minute"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
}

// GetUsers handles paginated user list endpoint
func (h *AdminHandler) GetUsers(ctx *fasthttp.RequestCtx) {
	// Get admin user ID for audit logging
	adminUserID := ctx.UserValue("user_id")
	log.Printf("ADMIN_ACCESS: User %v accessed user list (IP: %s)", adminUserID, ctx.RemoteIP())
	// Parse and validate page parameter
	pageStr := string(ctx.QueryArgs().Peek("page"))
	if pageStr == "" {
		pageStr = "1"
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}
	// Prevent extremely large page numbers that could cause database issues
	if page > 10000 {
		page = 10000
	}

	// Parse and validate page_size parameter
	pageSizeStr := string(ctx.QueryArgs().Peek("page_size"))
	if pageSizeStr == "" {
		pageSizeStr = "10"
	}
	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 {
		pageSize = 10
	}
	// Enforce reasonable limits: min 1, max 100
	if pageSize > 100 {
		pageSize = 100
	}

	// Calculate offset with bounds checking
	offset := (page - 1) * pageSize
	
	// Prevent extremely large offsets that could cause performance issues
	maxOffset := int64(1000000) // 1M limit
	if int64(offset) > maxOffset {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(`{"error":"Page number too large"}`)
		ctx.SetContentType("application/json")
		return
	}

	// Get total count with timeout context
	var total int64
	if err := h.db.Model(&database.User{}).Count(&total).Error; err != nil {
		log.Printf("ADMIN_ERROR: Failed to count users: %v", err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error":"Failed to count users"}`)
		ctx.SetContentType("application/json")
		return
	}

	// Get users with pagination and proper error handling
	var users []database.User
	err = h.db.Order("created_at DESC").
		Offset(offset).
		Limit(pageSize).
		Find(&users).Error
	if err != nil {
		log.Printf("ADMIN_ERROR: Failed to fetch users (page=%d, size=%d, offset=%d): %v", page, pageSize, offset, err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error":"Failed to fetch users"}`)
		ctx.SetContentType("application/json")
		return
	}

	// Convert to response format
	userInfos := make([]UserInfo, len(users))
	for i, user := range users {
		userInfos[i] = UserInfo{
			ID:                   user.ID.String(),
			Email:                user.Email,
			Name:                 user.Name,
			IsAdmin:              user.IsAdmin,
			MaxRequestsPerMinute: user.MaxRequestsPerMinute,
			CreatedAt:            user.CreatedAt.Format("2006-01-02 15:04:05"),
			UpdatedAt:            user.UpdatedAt.Format("2006-01-02 15:04:05"),
		}
	}

	// Calculate total pages
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	response := UserListResponse{
		Users:      userInfos,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
	}

	// Send response
	ctx.SetContentType("application/json")
	if err := json.NewEncoder(ctx).Encode(response); err != nil {
		log.Printf("ADMIN_ERROR: Failed to encode user list response: %v", err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error":"Failed to encode response"}`)
		return
	}

	// Audit log successful operation
	log.Printf("ADMIN_SUCCESS: User %v retrieved %d users (page %d/%d, total: %d)", 
		adminUserID, len(users), page, response.TotalPages, total)
}

// RegisterRoutes registers all admin routes
func (h *AdminHandler) RegisterRoutes(r *router.Router, adminMiddleware *AdminMiddleware) {
	r.GET("/api/admin/users", adminMiddleware.Handler(h.GetUsers))
}