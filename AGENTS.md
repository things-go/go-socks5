# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Overview

This repository implements a SOCKS5 proxy server library in Go. It provides a flexible, extensible SOCKS5 server with support for TCP/UDP, IPv4/IPv6, authentication, custom rules, DNS resolution, buffer pooling, and goroutine pooling. The library is designed as a package (`github.com/things-go/go-socks5`) that can be embedded in other applications.

## Architecture

### Core Components

- **Server** (`server.go`): Main entry point. Created via `NewServer` with functional options (`option.go`). Handles incoming connections, authentication, and request routing.
- **Request Handling** (`handle.go`): Processes CONNECT, BIND, and ASSOCIATE commands. CONNECT proxies TCP traffic; ASSOCIATE handles UDP tunneling; BIND is not yet implemented (TODO).
- **Authentication** (`auth.go`): Pluggable authenticators (`Authenticator` interface). Built-in `NoAuthAuthenticator` and `UserPassAuthenticator`. Credentials are validated via `CredentialStore` (`credentials.go`).
- **Rules** (`ruleset.go`): `RuleSet` interface for allowing/denying commands. Default `PermitCommand` provides simple command-based filtering.
- **Resolver** (`resolver.go`): `NameResolver` interface for custom DNS resolution. Default `DNSResolver` uses system DNS.
- **Buffer Pool** (`bufferpool/pool.go`): `BufPool` interface for efficient buffer reuse. Default pool with 32KB buffers.
- **Logger** (`logger.go`): `Logger` interface for error logging. Default logs to `io.Discard`.
- **Statute Package** (`statute/`): Constants, structs, and parsers for SOCKS5 protocol messages (method request, user/password auth, datagrams, addresses).

### Extensibility

The server is configured via functional options (`With*` functions in `option.go`). Key extension points:
- **Authenticator**: Add custom auth methods.
- **CredentialStore**: Validate username/password (optional user address limit).
- **RuleSet**: Custom logic to allow/deny requests.
- **NameResolver**: Custom DNS resolution.
- **AddressRewriter**: Transparently rewrite destination addresses.
- **GPool**: Custom goroutine pool (default uses plain goroutines).
- **Dial functions**: Custom dialers for outbound connections.
- **Middleware**: Per-command middleware chains (Connect, Bind, Associate).
- **User Handlers**: Override default handling for each command.

### Flow

1. Client connects → server negotiates authentication (selects from available methods).
2. Client sends request (CONNECT/BIND/ASSOCIATE) with destination address.
3. Server resolves FQDN (if any), applies address rewrite, checks rules.
4. If allowed, executes command-specific handler (with optional middleware and user override).
5. CONNECT: establishes TCP proxy between client and target.
6. ASSOCIATE: sets up UDP relay, managing bidirectional datagrams between client and remote hosts.
7. BIND: not implemented (returns command not supported).

### Concurrency

- Each connection is handled in its own goroutine (or via custom goroutine pool).
- UDP association uses a single UDP listener per association, with a sync.Map tracking per‑target connections.
- Buffer pooling reduces allocations for data copying.

## Common Commands

### Testing
```bash
# Run all tests with race detection and coverage
go test -v -race -coverprofile=coverage -covermode=atomic ./...

# Run tests for a specific package
go test ./statute
```

### Linting
```bash
# Uses golangci-lint with specific checkers (see .github/workflows/lint.yml)
golangci-lint run -E misspell,whitespace,unconvert,noctx,musttag,errchkjson,errname,exhaustive,exptostd ./...
```

### Building
```bash
# Build the package (no executable; library only)
go build ./...

# Build the example server
cd _example && go build
```

### Example Server
```bash
# Run the example server (listens on :10800)
cd _example && go run main.go
```

### Module Management
```bash
# Ensure dependencies are up-to-date
go mod tidy

# Verify dependencies
go mod verify
```

## Development Notes

- **Go version**: 1.18+ (module supports up to 1.26.x per CI matrix).
- **Dependencies**: Minimal (`golang.org/x/net`, `github.com/stretchr/testify` for tests).
- **Testing**: Use `-race` flag for data‑race detection. Coverage reports are uploaded to Codecov.
- **Linting**: The CI runs a subset of golangci-lint checkers; you can run the same locally.
- **Error Handling**: The library logs errors via the configured `Logger`; it returns errors for fatal conditions.
- **Protocol Compliance**: Implements RFC 1928 (SOCKS5). BIND command is not yet supported (TODO).
- **Example**: The example server (`_example/main.go`) listens on `:10800`; the README shows `:8000` for illustration.
- **Buffer Pooling**: Default buffer size is 32KB. Custom pools must implement `bufferpool.BufPool`.
- **Goroutine Pool**: Optional; if not provided, each connection spawns a new goroutine.

## Repository Structure

```
.
├── server.go          # Main server type and ListenAndServe
├── handle.go          # Request handling (CONNECT, BIND, ASSOCIATE)
├── auth.go            # Authenticator interface and implementations
├── credentials.go     # CredentialStore interface
├── resolver.go        # NameResolver interface
├── ruleset.go         # RuleSet interface and PermitCommand
├── option.go          # Functional options for configuration
├── logger.go          # Logger interface
├── bufferpool/        # Buffer pool implementation
├── statute/           # Protocol constants, structs, parsers
├── _example/          # Example server usage
└── *.test.go          # Unit tests for each component
```

## Commit Conventions

Commit messages follow a loose conventional commit style:
- `fix:` for bug fixes (e.g., `fix: add defensive checks in handleAssociate to prevent panics`)
- `chore:` for maintenance tasks (e.g., `chore(deps): bump actions/cache from 4 to 5`)
- `feat:` for new features (rare, as library is stable)
- Merge commits for pull requests are auto‑generated.

PRs are automatically linted with `golangci-lint` (see `.github/workflows/pr_review_dog.yml`). Ensure your changes pass the same checks locally before submitting.

## Useful References

- [RFC 1928](https://www.ietf.org/rfc/rfc1928.txt) – SOCKS5 protocol specification.
- Original [armon/go-socks5](https://github.com/armon/go-socks5) library (this project is a fork/rewrite).
- GoDoc: https://godoc.org/github.com/things-go/go-socks5
