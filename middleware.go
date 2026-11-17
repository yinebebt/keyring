package keyring

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// MiddlewareOption configures Middleware.
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	onError func(*http.Request, error)
}

// OnError is called when the keys can't be read. The request still gets 401;
// this is for logging why.
func OnError(fn func(*http.Request, error)) MiddlewareOption {
	return func(c *middlewareConfig) { c.onError = fn }
}

// Middleware is optional HTTP sugar around ValidKeys. Prefer ValidKeys for custom auth.
func Middleware(kr *Keyring, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	var cfg middlewareConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keys, err := kr.ValidKeys(r.Context())
			if err != nil && cfg.onError != nil {
				cfg.onError(r, err)
			}
			if err != nil || len(keys) == 0 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			token := r.Header.Get("X-API-Key")
			if token == "" {
				token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			}
			tokenBytes := []byte(token)
			for _, key := range keys {
				if subtle.ConstantTimeCompare(tokenBytes, []byte(key)) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}
}
