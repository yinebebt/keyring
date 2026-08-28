# keyring

Zero-downtime API key rotation.

Generate a new key, keep the old one valid during a grace period, then revoke it. One flat package, a file-backed store adapter, and optional HTTP middleware.

## Why

Rotating API keys without downtime means:

1. Generate a new key
2. Deploy it to consumers
3. Keep the old key valid for a grace period
4. Revoke the old key once everything has switched

`keyring` owns that state machine. Secret backends (AWS Secrets Manager, Vault KV) are adapters for a later version.

## Storage model

One **KeySet** per rotation slot — typically **one JSON file per service**:

```
keys/deeplink.json   # deeplink API
keys/webhook.json    # webhook API
```

Each file holds a `current` key, an optional `previous` key during grace, and rotation metadata. For multiple protected surfaces, use one file (and one `Keyring`) per surface.

## Install

```bash
go install github.com/yinebebt/keyring/cmd/keyring@latest
```

## CLI

```bash
# First rotation — creates current key (one file per service)
keyring rotate -file keys.json

# Rotate again — old key moves to previous, grace period starts
keyring rotate -file keys.json -grace 24h

# Check state
keyring status -file keys.json

# End grace period early
keyring revoke -file keys.json
```

Example `keys.json` after rotation:

```json
{
  "current": "kr_a1b2...",
  "previous": "kr_c3d4...",
  "grace_until": "2026-08-29T19:00:00Z",
  "rotated_at": "2026-08-28T19:00:00Z"
}
```

## Library

```go
store := keyring.NewFileStore("keys.json") // *FileStore, satisfies Store
kr := keyring.New(store, 24*time.Hour)

ks, err := kr.Rotate(ctx)
keys, err := kr.ValidKeys(ctx) // current + previous during grace
```

`New` accepts a `Store`; adapters return their concrete type (`*FileStore`) and satisfy the interface implicitly.

### HTTP middleware (optional)

Sugar around `ValidKeys` for `net/http` servers. Accepts `X-API-Key` or `Authorization: Bearer <key>`. GET/HEAD/OPTIONS are not protected.

```go
handler := keyring.Middleware(kr)(mux)
```

Prefer `ValidKeys` directly if you already have auth middleware. Keys are reloaded on every request, so file-backed stores pick up rotations without a restart.

## Rotation flow

```
ACTIVE  →  rotate  →  GRACE (current + previous valid)
GRACE   →  revoke  →  ACTIVE (previous cleared)
GRACE   →  grace_until expires  →  previous rejected by ValidKeys
```

## Tests & examples

```bash
go test ./...
```

Godoc examples live in `keyring_test.go` (`ExampleNew`, `ExampleMiddleware`).

## Roadmap

- AWS Secrets Manager adapter
- Vault KV adapter
- k8s Secret hot-reload example
- SOC2 / backend comparison docs

## License

MIT
