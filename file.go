package keyring

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var _ Store = (*FileStore)(nil)

// FileStore persists one KeySet as JSON at path.
type FileStore struct {
	path string
	mu   sync.Mutex
}

// NewFileStore returns a Store backed by a JSON file.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// Get reads the KeySet from disk. A missing file is treated as empty.
func (f *FileStore) Get(_ context.Context) (KeySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return KeySet{}, nil
		}
		return KeySet{}, fmt.Errorf("read %s: %w", f.path, err)
	}

	var ks KeySet
	if err := json.Unmarshal(data, &ks); err != nil {
		return KeySet{}, fmt.Errorf("decode %s: %w", f.path, err)
	}
	return ks, nil
}

// Put writes the KeySet to disk atomically with mode 0600.
func (f *FileStore) Put(_ context.Context, ks KeySet) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(f.path), err)
	}

	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return fmt.Errorf("encode key set: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".keyring-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, f.path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
