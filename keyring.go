package keyring

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

const defaultPrefix = "kr_"

// Keyring orchestrates API key rotation for one KeySet via a Store.
type Keyring struct {
	store  Store
	grace  time.Duration
	prefix string
	now    func() time.Time
}

// Option configures a Keyring.
type Option func(*Keyring)

// WithPrefix sets the generated key prefix. Default is "kr_".
func WithPrefix(prefix string) Option {
	return func(k *Keyring) {
		k.prefix = prefix
	}
}

// WithClock overrides the time source. Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(k *Keyring) {
		k.now = now
	}
}

// New returns a Keyring that uses store with the given grace period.
func New(store Store, grace time.Duration, opts ...Option) *Keyring {
	k := &Keyring{
		store:  store,
		grace:  grace,
		prefix: defaultPrefix,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(k)
	}
	return k
}

// Rotate generates a new key, moves the current key to previous, and starts
// the grace period. On first rotation (empty store), only current is set.
func (k *Keyring) Rotate(ctx context.Context) (KeySet, error) {
	ks, err := k.store.Get(ctx)
	if err != nil {
		return KeySet{}, fmt.Errorf("get key set: %w", err)
	}

	newKey, err := generateKey(k.prefix)
	if err != nil {
		return KeySet{}, fmt.Errorf("generate key: %w", err)
	}

	now := k.now()
	updated := KeySet{
		Current:   newKey,
		RotatedAt: &now,
	}

	if ks.Current != "" {
		updated.Previous = ks.Current
		until := now.Add(k.grace)
		updated.GraceUntil = &until
	}

	if err := k.store.Put(ctx, updated); err != nil {
		return KeySet{}, fmt.Errorf("put key set: %w", err)
	}
	return updated, nil
}

// Revoke clears the previous key and ends the grace period immediately.
func (k *Keyring) Revoke(ctx context.Context) (KeySet, error) {
	ks, err := k.store.Get(ctx)
	if err != nil {
		return KeySet{}, fmt.Errorf("get key set: %w", err)
	}
	if ks.Current == "" {
		return KeySet{}, fmt.Errorf("no active key to revoke against")
	}

	updated := KeySet{
		Current:   ks.Current,
		RotatedAt: ks.RotatedAt,
	}
	if err := k.store.Put(ctx, updated); err != nil {
		return KeySet{}, fmt.Errorf("put key set: %w", err)
	}
	return updated, nil
}

// Status returns the current KeySet from the store.
func (k *Keyring) Status(ctx context.Context) (KeySet, error) {
	ks, err := k.store.Get(ctx)
	if err != nil {
		return KeySet{}, fmt.Errorf("get key set: %w", err)
	}
	return ks, nil
}

// ValidKeys returns keys that should be accepted for auth right now.
func (k *Keyring) ValidKeys(ctx context.Context) ([]string, error) {
	ks, err := k.store.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("get key set: %w", err)
	}
	return ks.ValidKeys(k.now()), nil
}

func generateKey(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}
