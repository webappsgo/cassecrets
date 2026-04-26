package auth

import (
	"database/sql"
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements rate limiting for API endpoints
type RateLimiter struct {
	db          *sql.DB
	limits      map[string]*limitConfig
	buckets     map[string]*bucket
	mu          sync.RWMutex
	cleanupTick *time.Ticker
	stopCleanup chan struct{}
}

type limitConfig struct {
	requests int
	window   time.Duration
}

type bucket struct {
	requests []time.Time
	mu       sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(db *sql.DB) *RateLimiter {
	rl := &RateLimiter{
		db:          db,
		limits:      make(map[string]*limitConfig),
		buckets:     make(map[string]*bucket),
		stopCleanup: make(chan struct{}),
	}

	// Set default limits
	rl.limits["login"] = &limitConfig{requests: 5, window: 15 * time.Minute}
	rl.limits["register"] = &limitConfig{requests: 3, window: time.Hour}
	rl.limits["password_reset"] = &limitConfig{requests: 3, window: time.Hour}
	rl.limits["api"] = &limitConfig{requests: 100, window: time.Minute}
	rl.limits["api_key_create"] = &limitConfig{requests: 10, window: time.Hour}

	// Start cleanup goroutine
	rl.cleanupTick = time.NewTicker(5 * time.Minute)
	go rl.cleanup()

	return rl
}

// SetLimit configures a rate limit for an endpoint type
func (rl *RateLimiter) SetLimit(endpoint string, requests int, window time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.limits[endpoint] = &limitConfig{requests: requests, window: window}
}

// Allow checks if a request should be allowed
func (rl *RateLimiter) Allow(endpoint, identifier string) bool {
	rl.mu.RLock()
	limit, exists := rl.limits[endpoint]
	rl.mu.RUnlock()

	if !exists {
		return true
	}

	key := endpoint + ":" + identifier

	rl.mu.Lock()
	b, exists := rl.buckets[key]
	if !exists {
		b = &bucket{requests: make([]time.Time, 0)}
		rl.buckets[key] = b
	}
	rl.mu.Unlock()

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-limit.window)

	// Remove expired requests
	valid := make([]time.Time, 0, len(b.requests))
	for _, t := range b.requests {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}
	b.requests = valid

	// Check if under limit
	if len(b.requests) >= limit.requests {
		return false
	}

	// Add current request
	b.requests = append(b.requests, now)
	return true
}

// Remaining returns the number of remaining requests
func (rl *RateLimiter) Remaining(endpoint, identifier string) int {
	rl.mu.RLock()
	limit, exists := rl.limits[endpoint]
	rl.mu.RUnlock()

	if !exists {
		return -1
	}

	key := endpoint + ":" + identifier

	rl.mu.RLock()
	b, exists := rl.buckets[key]
	rl.mu.RUnlock()

	if !exists {
		return limit.requests
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-limit.window)

	count := 0
	for _, t := range b.requests {
		if t.After(windowStart) {
			count++
		}
	}

	remaining := limit.requests - count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Reset clears rate limit for an identifier
func (rl *RateLimiter) Reset(endpoint, identifier string) {
	key := endpoint + ":" + identifier

	rl.mu.Lock()
	delete(rl.buckets, key)
	rl.mu.Unlock()
}

// cleanup removes expired buckets
func (rl *RateLimiter) cleanup() {
	for {
		select {
		case <-rl.cleanupTick.C:
			rl.mu.Lock()
			now := time.Now()

			for key, b := range rl.buckets {
				b.mu.Lock()
				// Find the endpoint from key
				endpoint := ""
				for e := range rl.limits {
					if len(key) > len(e)+1 && key[:len(e)] == e {
						endpoint = e
						break
					}
				}

				if endpoint == "" {
					b.mu.Unlock()
					continue
				}

				limit := rl.limits[endpoint]
				windowStart := now.Add(-limit.window)

				// Remove expired requests
				valid := make([]time.Time, 0)
				for _, t := range b.requests {
					if t.After(windowStart) {
						valid = append(valid, t)
					}
				}

				if len(valid) == 0 {
					b.mu.Unlock()
					delete(rl.buckets, key)
				} else {
					b.requests = valid
					b.mu.Unlock()
				}
			}
			rl.mu.Unlock()

		case <-rl.stopCleanup:
			return
		}
	}
}

// Stop stops the rate limiter cleanup goroutine
func (rl *RateLimiter) Stop() {
	rl.cleanupTick.Stop()
	close(rl.stopCleanup)
}

// RateLimitMiddleware creates a middleware for rate limiting
func (rl *RateLimiter) RateLimitMiddleware(endpoint string, getIdentifier func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identifier := getIdentifier(r)
			if identifier == "" {
				identifier = getClientIP(r)
			}

			if !rl.Allow(endpoint, identifier) {
				http.Error(w, `{"error":"Too many requests","code":"RATE_LIMITED","status":429}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take first IP
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Use RemoteAddr
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

// GetClientIP is exported for use in handlers
func GetClientIP(r *http.Request) string {
	return getClientIP(r)
}
