package keyring_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yinebebt/keyring"
)

func testKeyring(t *testing.T) *keyring.Keyring {
	t.Helper()
	return keyring.New(
		keyring.NewFileStore(filepath.Join(t.TempDir(), "keys.json")),
		time.Hour,
	)
}

func mustRotate(t *testing.T, kr *keyring.Keyring) keyring.KeySet {
	t.Helper()
	ks, err := kr.Rotate(context.Background())
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	return ks
}

func TestKeySetState(t *testing.T) {
	t.Parallel()

	now := time.Now()
	inGrace := now.Add(time.Hour)
	expired := now.Add(-time.Hour)

	for _, tt := range []struct {
		name  string
		ks    keyring.KeySet
		at    time.Time
		state keyring.State
		keys  int
	}{
		{"empty", keyring.KeySet{}, now, keyring.StateEmpty, 0},
		{"active", keyring.KeySet{Current: "kr_a"}, now, keyring.StateActive, 1},
		{
			"grace",
			keyring.KeySet{Current: "kr_b", Previous: "kr_a", GraceUntil: &inGrace},
			now,
			keyring.StateGrace,
			2,
		},
		{
			"expired",
			keyring.KeySet{Current: "kr_b", Previous: "kr_a", GraceUntil: &expired},
			now,
			keyring.StateActive,
			1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.ks.State(tt.at); got != tt.state {
				t.Fatalf("State() = %s, want %s", got, tt.state)
			}
			if got := len(tt.ks.ValidKeys()); got != tt.keys {
				t.Fatalf("ValidKeys() = %d, want %d", got, tt.keys)
			}
		})
	}
}

func TestRotation(t *testing.T) {
	t.Parallel()

	kr := testKeyring(t)
	now := time.Now()

	first := mustRotate(t, kr)
	if first.Previous != "" || first.GraceUntil != nil || first.State(now) != keyring.StateActive {
		t.Fatal("first rotation should only set current")
	}

	beforeSecond := time.Now()
	second := mustRotate(t, kr)
	if second.Previous != first.Current || second.State(now) != keyring.StateGrace {
		t.Fatal("second rotation should enter grace")
	}
	if second.GraceUntil == nil || second.GraceUntil.Before(beforeSecond.Add(time.Hour)) {
		t.Fatalf("grace_until = %v, want ~%v", second.GraceUntil, beforeSecond.Add(time.Hour))
	}

	keys, err := kr.ValidKeys(context.Background())
	if err != nil || len(keys) != 2 {
		t.Fatalf("during grace: keys = %v, err = %v", keys, err)
	}

	revoked, err := kr.Revoke(context.Background())
	if err != nil || revoked.Previous != "" || revoked.GraceUntil != nil {
		t.Fatalf("revoke: ks = %+v, err = %v", revoked, err)
	}
}

func TestMiddleware(t *testing.T) {
	t.Parallel()

	kr := testKeyring(t)
	first := mustRotate(t, kr)
	second := mustRotate(t, kr)

	handler := keyring.Middleware(kr)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, tt := range []struct {
		method, token, header string
		want                  int
	}{
		{http.MethodGet, "", "", http.StatusUnauthorized},
		{http.MethodHead, "", "", http.StatusUnauthorized},
		{http.MethodOptions, "", "", http.StatusUnauthorized},
		{http.MethodPost, second.Current, "X-API-Key", http.StatusOK},
		{http.MethodPost, first.Current, "X-API-Key", http.StatusOK},
		{http.MethodPost, second.Current, "Authorization", http.StatusOK},
		{http.MethodPost, "bad-key", "X-API-Key", http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(tt.method, "/", nil)
		switch tt.header {
		case "X-API-Key":
			req.Header.Set("X-API-Key", tt.token)
		case "Authorization":
			req.Header.Set("Authorization", "Bearer "+tt.token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Fatalf("%s token=%q: status = %d, want %d", tt.method, tt.token, rec.Code, tt.want)
		}
	}
}

func TestFileStore(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "keys.json")
	store := keyring.NewFileStore(path)
	want := keyring.KeySet{Current: "kr_test"}

	if err := store.Put(context.Background(), want); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := store.Get(context.Background())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestRotateInGrace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	kr := testKeyring(t)
	mustRotate(t, kr)
	second := mustRotate(t, kr)
	if _, err := kr.Rotate(ctx); !errors.Is(err, keyring.ErrInGrace) {
		t.Fatalf("rotate in grace: err = %v, want ErrInGrace", err)
	}
	if ks, _ := kr.Status(ctx); ks.Current != second.Current || ks.Previous != second.Previous {
		t.Fatalf("refused rotate changed the key set: %+v", ks)
	}
	if _, err := kr.Revoke(ctx); err != nil {
		t.Fatal(err)
	}
	mustRotate(t, kr)

	// Once grace has expired, rotating needs no revoke.
	expired := keyring.New(keyring.NewFileStore(filepath.Join(t.TempDir(), "keys.json")), time.Nanosecond)
	mustRotate(t, expired)
	mustRotate(t, expired)
	time.Sleep(time.Millisecond)
	mustRotate(t, expired)
}

type failingStore struct{ err error }

func (f failingStore) Get(context.Context) (keyring.KeySet, error) { return keyring.KeySet{}, f.err }
func (f failingStore) Put(context.Context, keyring.KeySet) error   { return f.err }

func TestMiddlewareOnError(t *testing.T) {
	t.Parallel()

	storeErr := errors.New("store down")
	var got error
	handler := keyring.Middleware(
		keyring.New(failingStore{storeErr}, time.Hour),
		keyring.OnError(func(_ *http.Request, err error) { got = err }),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "kr_any")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !errors.Is(got, storeErr) {
		t.Fatalf("OnError got %v, want %v", got, storeErr)
	}
}

func exampleSetup() (*keyring.Keyring, func(), error) {
	dir, err := os.MkdirTemp("", "keyring-example-*")
	if err != nil {
		return nil, nil, err
	}
	kr := keyring.New(keyring.NewFileStore(filepath.Join(dir, "keys.json")), time.Hour)
	return kr, func() { _ = os.RemoveAll(dir) }, nil
}

func ExampleNew() {
	kr, cleanup, err := exampleSetup()
	if err != nil {
		panic(err)
	}
	defer cleanup()

	ks, err := kr.Rotate(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println(ks.State(time.Now()))
	// Output: ACTIVE
}

func ExampleMiddleware() {
	kr, cleanup, err := exampleSetup()
	if err != nil {
		panic(err)
	}
	defer cleanup()

	ks, err := kr.Rotate(context.Background())
	if err != nil {
		panic(err)
	}

	handler := keyring.Middleware(kr)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-API-Key", ks.Current)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	fmt.Println(rec.Code)
	// Output: 200
}
