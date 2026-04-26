package api

import (
	"net/http"

	"github.com/casapps/cassecrets/src/auth"
)

// Router sets up API routes
type Router struct {
	api           *API
	authenticator *auth.Authenticator
	rateLimiter   *auth.RateLimiter
}

// NewRouter creates a new API router
func NewRouter(api *API, authenticator *auth.Authenticator, rateLimiter *auth.RateLimiter) *Router {
	return &Router{
		api:           api,
		authenticator: authenticator,
		rateLimiter:   rateLimiter,
	}
}

// SetupRoutes registers all API routes with the provided mux
func (r *Router) SetupRoutes(mux *http.ServeMux) {
	// Health check
	mux.HandleFunc("GET /api/health", r.healthCheck)

	// Auth routes (public)
	mux.HandleFunc("POST /api/auth/login", r.api.Auth.Login)
	mux.HandleFunc("POST /api/auth/register", r.api.Auth.Register)
	mux.HandleFunc("POST /api/auth/refresh", r.api.Auth.Refresh)

	// Auth routes (protected)
	mux.Handle("POST /api/auth/logout", r.requireAuth(http.HandlerFunc(r.api.Auth.Logout)))
	mux.Handle("GET /api/auth/me", r.requireAuth(http.HandlerFunc(r.api.Auth.Me)))
	mux.Handle("POST /api/auth/password", r.requireAuth(http.HandlerFunc(r.api.Auth.ChangePassword)))

	// User routes
	mux.Handle("GET /api/users/me", r.requireAuth(http.HandlerFunc(r.api.Users.Get)))
	mux.Handle("PUT /api/users/me", r.requireAuth(http.HandlerFunc(r.api.Users.Update)))
	mux.Handle("PATCH /api/users/me", r.requireAuth(http.HandlerFunc(r.api.Users.Update)))
	mux.Handle("DELETE /api/users/me", r.requireAuth(http.HandlerFunc(r.api.Users.Delete)))
	mux.Handle("GET /api/users/me/teams", r.requireAuth(http.HandlerFunc(r.api.Users.ListTeams)))
	mux.Handle("GET /api/users/{id}", r.requireAuth(http.HandlerFunc(r.api.Users.Get)))
	mux.Handle("PUT /api/users/{id}", r.requireAuth(http.HandlerFunc(r.api.Users.Update)))
	mux.Handle("PATCH /api/users/{id}", r.requireAuth(http.HandlerFunc(r.api.Users.Update)))
	mux.Handle("DELETE /api/users/{id}", r.requireAuth(http.HandlerFunc(r.api.Users.Delete)))

	// Team routes
	mux.Handle("GET /api/teams", r.requireAuth(http.HandlerFunc(r.api.Teams.List)))
	mux.Handle("POST /api/teams", r.requireAuth(http.HandlerFunc(r.api.Teams.Create)))
	mux.Handle("GET /api/teams/{id}", r.requireAuth(http.HandlerFunc(r.api.Teams.Get)))
	mux.Handle("PUT /api/teams/{id}", r.requireAuth(http.HandlerFunc(r.api.Teams.Update)))
	mux.Handle("PATCH /api/teams/{id}", r.requireAuth(http.HandlerFunc(r.api.Teams.Update)))
	mux.Handle("DELETE /api/teams/{id}", r.requireAuth(http.HandlerFunc(r.api.Teams.Delete)))

	// Team member routes
	mux.Handle("GET /api/teams/{id}/members", r.requireAuth(http.HandlerFunc(r.api.Teams.ListMembers)))
	mux.Handle("POST /api/teams/{id}/members", r.requireAuth(http.HandlerFunc(r.api.Teams.AddMember)))
	mux.Handle("PUT /api/teams/{id}/members/{user_id}", r.requireAuth(http.HandlerFunc(r.api.Teams.UpdateMember)))
	mux.Handle("PATCH /api/teams/{id}/members/{user_id}", r.requireAuth(http.HandlerFunc(r.api.Teams.UpdateMember)))
	mux.Handle("DELETE /api/teams/{id}/members/{user_id}", r.requireAuth(http.HandlerFunc(r.api.Teams.RemoveMember)))
	mux.Handle("POST /api/teams/{id}/transfer", r.requireAuth(http.HandlerFunc(r.api.Teams.TransferOwnership)))

	// Secret routes
	mux.Handle("GET /api/secrets", r.requireAuth(http.HandlerFunc(r.api.Secrets.List)))
	mux.Handle("POST /api/secrets", r.requireAuth(http.HandlerFunc(r.api.Secrets.Create)))
	mux.Handle("GET /api/secrets/by-path", r.requireAuth(http.HandlerFunc(r.api.Secrets.GetByPath)))
	mux.Handle("GET /api/secrets/{id}", r.requireAuth(http.HandlerFunc(r.api.Secrets.Get)))
	mux.Handle("PUT /api/secrets/{id}", r.requireAuth(http.HandlerFunc(r.api.Secrets.Update)))
	mux.Handle("PATCH /api/secrets/{id}", r.requireAuth(http.HandlerFunc(r.api.Secrets.Update)))
	mux.Handle("DELETE /api/secrets/{id}", r.requireAuth(http.HandlerFunc(r.api.Secrets.Delete)))
	mux.Handle("GET /api/secrets/{id}/versions", r.requireAuth(http.HandlerFunc(r.api.Secrets.GetVersions)))
	mux.Handle("POST /api/secrets/{id}/rollback", r.requireAuth(http.HandlerFunc(r.api.Secrets.Rollback)))

	// Team-scoped secret routes
	mux.Handle("GET /api/teams/{team_id}/secrets", r.requireAuth(http.HandlerFunc(r.api.Secrets.List)))
	mux.Handle("POST /api/teams/{team_id}/secrets", r.requireAuth(http.HandlerFunc(r.api.Secrets.Create)))

	// API key routes
	mux.Handle("GET /api/apikeys", r.requireAuth(http.HandlerFunc(r.api.APIKeys.List)))
	mux.Handle("POST /api/apikeys", r.requireAuth(http.HandlerFunc(r.api.APIKeys.Create)))
	mux.Handle("GET /api/apikeys/{id}", r.requireAuth(http.HandlerFunc(r.api.APIKeys.Get)))
	mux.Handle("DELETE /api/apikeys/{id}", r.requireAuth(http.HandlerFunc(r.api.APIKeys.Delete)))
	mux.Handle("POST /api/apikeys/{id}/rotate", r.requireAuth(http.HandlerFunc(r.api.APIKeys.Rotate)))
	mux.Handle("POST /api/apikeys/{id}/enable", r.requireAuth(http.HandlerFunc(r.api.APIKeys.Enable)))
	mux.Handle("POST /api/apikeys/{id}/disable", r.requireAuth(http.HandlerFunc(r.api.APIKeys.Disable)))
}

// requireAuth wraps a handler with authentication
func (r *Router) requireAuth(next http.Handler) http.Handler {
	return r.authenticator.RequireAuth(next)
}

// healthCheck handles health check requests
func (r *Router) healthCheck(w http.ResponseWriter, req *http.Request) {
	writeSuccess(w, map[string]string{
		"status":  "healthy",
		"service": "cassecrets",
	})
}
