# Agent notes

- This is a single Go `main` package; proxy, config, and CLI logic live in `main.go`, with tests in `main_test.go`.
- Go version is pinned by `go.mod` (Go 1.25.9). Run `go test ./...`; focus a test with `go test -run '^TestName$' .` (or a subtest via `-run 'TestName/subtest'`).
- Before delivery, run `go vet ./...` as well as the relevant tests. CI additionally runs `govulncheck ./...` (install with `go install golang.org/x/vuln/cmd/govulncheck@latest`).
- Use Conventional Commit subjects: lowercase type and colon, e.g. `feat: ...`, `fix: ...`, or `chore: ...` (as in recent history).
- Config parsing, policy evaluation, and proxy request handling are security-sensitive. Preserve blacklist-before-whitelist behavior and per-user override precedence; use the README's documented semantics when changing policy.
- The release workflow builds standalone binaries from `main.go` with `CGO_ENABLED=0` for Linux amd64 and arm64, then publishes a multi-arch Docker image. Do not rely on cgo or checked-in generated/container build files; the workflow generates its Dockerfile during release.
