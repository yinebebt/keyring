package keyring

import (
	"context"
	"time"
)

// State describes the rotation lifecycle of a KeySet.
type State string

const (
	StateEmpty  State = "EMPTY"
	StateActive State = "ACTIVE"
	StateGrace  State = "GRACE"
)

// KeySet is the rotation state for one API key slot: a current key, an optional
// previous key during grace, and rotation metadata. One KeySet per service.
type KeySet struct {
	Current    string     `json:"current"`
	Previous   string     `json:"previous"`
	GraceUntil *time.Time `json:"grace_until,omitempty"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
}

// State returns the lifecycle state at the given time.
func (k KeySet) State(now time.Time) State {
	if k.Current == "" {
		return StateEmpty
	}
	if k.Previous != "" && k.GraceUntil != nil && now.Before(*k.GraceUntil) {
		return StateGrace
	}
	return StateActive
}

// ValidKeys returns keys that should be accepted by auth middleware at now.
// Previous is omitted once the grace period has expired.
func (k KeySet) ValidKeys(now time.Time) []string {
	var keys []string
	if k.Current != "" {
		keys = append(keys, k.Current)
	}
	if k.Previous != "" && k.GraceUntil != nil && now.Before(*k.GraceUntil) {
		keys = append(keys, k.Previous)
	}
	return keys
}

// Store persists a single KeySet (one rotation slot). Use one store per service;
// for multiple surfaces, use separate files or secret paths. Implementations
// must be safe for concurrent use within a process.
type Store interface {
	Get(ctx context.Context) (KeySet, error)
	Put(ctx context.Context, ks KeySet) error
}
