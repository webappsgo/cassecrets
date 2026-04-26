package auth

import (
	"context"
	"net/http"
	"strings"
)

// Context keys for authenticated user info
type contextKey string

const (
	ContextKeyUserID   contextKey = "user_id"
	ContextKeyUserType contextKey = "user_type"
	ContextKeyScopes   contextKey = "scopes"
	ContextKeyClaims   contextKey = "claims"
	ContextKeySession  contextKey = "session"
)

// Authenticator handles authentication for HTTP requests
type Authenticator struct {
	jwtManager     *JWTManager
	sessionManager *SessionManager
	apiKeyRepo     *APIKeyRepository
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(jwt *JWTManager, session *SessionManager, apiKey *APIKeyRepository) *Authenticator {
	return &Authenticator{
		jwtManager:     jwt,
		sessionManager: session,
		apiKeyRepo:     apiKey,
	}
}

// RequireAuth middleware requires authentication via JWT or API key
func (a *Authenticator) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := a.authenticateRequest(r)
		if err != nil || claims == nil {
			http.Error(w, `{"error":"Unauthorized","code":"UNAUTHORIZED","status":401}`, http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), ContextKeyClaims, claims)
		ctx = context.WithValue(ctx, ContextKeyUserID, claims.UserID)
		ctx = context.WithValue(ctx, ContextKeyUserType, claims.UserType)
		ctx = context.WithValue(ctx, ContextKeyScopes, claims.Scopes)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireScopes middleware requires specific scopes
func (a *Authenticator) RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, `{"error":"Unauthorized","code":"UNAUTHORIZED","status":401}`, http.StatusUnauthorized)
				return
			}

			if !claims.HasAnyScope(scopes...) {
				http.Error(w, `{"error":"Forbidden","code":"FORBIDDEN","status":403}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin middleware requires admin authentication
func (a *Authenticator) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaimsFromContext(r.Context())
		if claims == nil || claims.UserType != "admin" {
			http.Error(w, `{"error":"Admin access required","code":"ADMIN_REQUIRED","status":403}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// OptionalAuth middleware adds auth info to context if present, but doesn't require it
func (a *Authenticator) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := a.authenticateRequest(r)
		if claims != nil {
			ctx := context.WithValue(r.Context(), ContextKeyClaims, claims)
			ctx = context.WithValue(ctx, ContextKeyUserID, claims.UserID)
			ctx = context.WithValue(ctx, ContextKeyUserType, claims.UserType)
			ctx = context.WithValue(ctx, ContextKeyScopes, claims.Scopes)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdminSession middleware requires admin session authentication
func (a *Authenticator) RequireAdminSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := GetSessionFromRequest(r, AdminSessionCookie)
		if token == "" {
			http.Redirect(w, r, "/auth/login?redirect="+r.URL.Path, http.StatusFound)
			return
		}

		session, err := a.sessionManager.GetAdminSession(token)
		if err != nil || session == nil {
			ClearSessionCookie(w, AdminSessionCookie)
			http.Redirect(w, r, "/auth/login?redirect="+r.URL.Path, http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), ContextKeySession, session)
		ctx = context.WithValue(ctx, ContextKeyUserID, session.UserID)
		ctx = context.WithValue(ctx, ContextKeyUserType, session.UserType)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireUserSession middleware requires user session authentication
func (a *Authenticator) RequireUserSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := GetSessionFromRequest(r, UserSessionCookie)
		if token == "" {
			http.Redirect(w, r, "/auth/login?redirect="+r.URL.Path, http.StatusFound)
			return
		}

		session, err := a.sessionManager.GetUserSession(token)
		if err != nil || session == nil {
			ClearSessionCookie(w, UserSessionCookie)
			http.Redirect(w, r, "/auth/login?redirect="+r.URL.Path, http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), ContextKeySession, session)
		ctx = context.WithValue(ctx, ContextKeyUserID, session.UserID)
		ctx = context.WithValue(ctx, ContextKeyUserType, session.UserType)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticateRequest attempts to authenticate the request
func (a *Authenticator) authenticateRequest(r *http.Request) (*Claims, error) {
	// Try Authorization header first
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Bearer token
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			return a.authenticateToken(token)
		}
	}

	// Try API key in X-API-Key header
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		return a.authenticateAPIKey(apiKey)
	}

	return nil, nil
}

// authenticateToken validates a JWT or API token
func (a *Authenticator) authenticateToken(token string) (*Claims, error) {
	// Try JWT first
	claims, err := a.jwtManager.ValidateToken(token)
	if err == nil {
		return claims, nil
	}

	// Try as API key (format: cassecrets_xxx or key_xxx)
	if strings.HasPrefix(token, "cassecrets_") || strings.HasPrefix(token, "key_") {
		return a.authenticateAPIKey(token)
	}

	return nil, err
}

// authenticateAPIKey validates an API key
func (a *Authenticator) authenticateAPIKey(key string) (*Claims, error) {
	if a.apiKeyRepo == nil {
		return nil, ErrInvalidToken
	}

	apiKey, err := a.apiKeyRepo.ValidateKey(key)
	if err != nil || apiKey == nil {
		return nil, ErrInvalidToken
	}

	// Convert API key to claims
	return &Claims{
		UserID:    apiKey.OwnerID,
		UserType:  apiKey.OwnerType,
		TokenType: TokenTypeAPI,
		Scopes:    apiKey.Scopes,
	}, nil
}

// GetClaimsFromContext retrieves claims from the request context
func GetClaimsFromContext(ctx context.Context) *Claims {
	claims, ok := ctx.Value(ContextKeyClaims).(*Claims)
	if !ok {
		return nil
	}
	return claims
}

// GetUserIDFromContext retrieves user ID from the request context
func GetUserIDFromContext(ctx context.Context) int64 {
	userID, ok := ctx.Value(ContextKeyUserID).(int64)
	if !ok {
		return 0
	}
	return userID
}

// GetUserTypeFromContext retrieves user type from the request context
func GetUserTypeFromContext(ctx context.Context) string {
	userType, ok := ctx.Value(ContextKeyUserType).(string)
	if !ok {
		return ""
	}
	return userType
}

// GetSessionFromContext retrieves session from the request context
func GetSessionFromContext(ctx context.Context) *Session {
	session, ok := ctx.Value(ContextKeySession).(*Session)
	if !ok {
		return nil
	}
	return session
}
