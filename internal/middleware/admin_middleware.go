package middleware

import (
	"log"

	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

// AdminMiddleware provides middleware to restrict access to admin-only routes
type AdminMiddleware struct {
	service *AuthService
}

// NewAdminMiddleware creates a new admin middleware instance
func NewAdminMiddleware(service *AuthService) *AdminMiddleware {
	return &AdminMiddleware{
		service: service,
	}
}

// Handler creates a FastHTTP middleware handler that checks for admin privileges
func (m *AdminMiddleware) Handler(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		// Get user ID from context (should be set by auth middleware)
		userIDValue := ctx.UserValue("user_id")
		if userIDValue == nil {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetBodyString(`{"error":"Authentication required"}`)
			ctx.SetContentType("application/json")
			return
		}

		userID, ok := userIDValue.(uuid.UUID)
		if !ok {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error":"Invalid user context"}`)
			ctx.SetContentType("application/json")
			return
		}

		// Check if user is admin
		isAdmin, err := m.service.IsUserAdmin(userID)
		if err != nil {
			log.Printf("Error checking admin status for user %s: %v", userID, err)
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString(`{"error":"Unable to verify admin status"}`)
			ctx.SetContentType("application/json")
			return
		}

		if !isAdmin {
			log.Printf("ADMIN_DENIED: Non-admin user %s attempted to access admin resource %s (IP: %s)", 
				userID, string(ctx.Path()), ctx.RemoteIP())
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetBodyString(`{"error":"Admin privileges required"}`)
			ctx.SetContentType("application/json")
			return
		}

		// User is admin, continue to next handler
		log.Printf("ADMIN_AUTHORIZED: Admin user %s accessing %s (IP: %s)", 
			userID, string(ctx.Path()), ctx.RemoteIP())
		next(ctx)
	}
}