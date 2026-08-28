package keyring

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Middleware is optional HTTP sugar around ValidKeys. Mutating methods require a
// valid key; GET, HEAD, and OPTIONS pass through. Prefer ValidKeys for custom auth.
func Middleware(kr *Keyring) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}

			keys, err := kr.ValidKeys(r.Context())
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
