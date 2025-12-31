# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2025-12-31

### Added
- **NEW**: `issuer` parameter for `Middleware#initialize` to optionally override the discovered issuer
  - When provided, the configured issuer takes precedence over the OIDC discovery document's issuer
  - This enables compatibility with `verikloak-rails` which passes `issuer` from configuration
  - If not provided, the middleware continues to use the issuer from OIDC discovery (existing behavior)

### Changed
- Internal issuer handling now distinguishes between `@configured_issuer` (user-provided) and `@issuer` (discovered/effective)
- When `jwks_cache` is injected, discovery is only fetched once (and skipped entirely if `issuer` is provided)

## [0.2.1] - 2025-09-23

### Changed
- **BREAKING**: `JwksCache` is now thread-safe with Mutex synchronization around all cache operations
- Middleware code organization: split large modules into focused, single-responsibility components:
  - `SkipPathMatcher`: Path matching and normalization logic
  - `MiddlewareAudienceResolution`: Audience resolution with dynamic callable support
  - `MiddlewareConfiguration`: Configuration validation and logging utilities
  - `MiddlewareDecoderCache`: LRU cache management for TokenDecoder instances
  - `MiddlewareTokenVerification`: JWT verification and JWKs management
  - `MiddlewareErrorMapping`: Error-to-HTTP status code mapping

### Fixed
- Removed duplicate method definitions that were causing code bloat
- Audience callable parameter detection now handles edge cases more reliably
- Thread-safety issues in concurrent environments resolved

## [0.2.0] - 2025-09-22

### Added
- Middleware options `token_env_key` and `user_env_key` for customizing where the token and decoded claims are stored in the Rack env.
- Middleware option `realm` to change the `WWW-Authenticate` realm value emitted on 401 responses.
- Middleware option `logger` so unexpected internal errors can be sent to the host application's logger instead of STDERR.

### Changed
- Update gem version to 0.2.0 to stay aligned with the rest of the Verikloak ecosystem gems.

## [0.1.5] - 2025-09-21

### Added
- Specs for `Verikloak::HTTP.default_connection`, ensuring retry middleware and timeout defaults stay in sync.

### Changed
- Middleware audience callables now handle zero-arity and BasicObject-style implementations without relying on `method(:call)`.
- README documents the shared `Verikloak::HTTP.default_connection` helper for reuse/customization.

### Dependencies
- Declare `faraday-retry` as a runtime dependency so the default HTTP connection can load the retry middleware.

## [0.1.4] - 2025-09-20

### Chore
- Bump dev dependency `rexml` to 3.4.2 (PR #15).

## [0.1.3] - 2025-09-15

### Changed
- Relax `jwt` runtime dependency to `>= 2.7, < 4.0` to allow jwt 3.x (PR #11).

### Chore
- Bump dev dependency `rubocop` to 1.80.2 (PR #13).
- Bump dev dependency `rubocop-rspec` to 3.7.0 (PR #12).

## [0.1.2] - 2025-08-31

### Added
- Middleware: new `connection:` option to inject a Faraday::Connection, shared by Discovery and JWKs.
- Middleware: new `leeway:` and `token_verify_options:` options, delegated to TokenDecoder.
- README: documented usage of `connection`, leeway/options, and clarified `skip_paths` behavior.

### Changed
- Middleware: `skip_paths` semantics clarified — plain paths are exact-match only, use `/*` for prefix matching.
- Middleware: TokenDecoder instances are now cached per JWKs fetch for performance improvement.
- Internal: RuboCop style fixes (`HashExcept`, `HashTransformKeys`, long line splits).

## [0.1.1] - 2025-08-24

### Changed

- Updated dependency constraints in gemspec (`json` ~> 2.6, `jwt` ~> 2.7) for better compatibility control
- Updated README badges (Gem version, Ruby version, downloads)

## [0.1.0] - 2025-08-17

### Added

- Initial release of `verikloak`
- Rack middleware for verifying JWT access tokens from Keycloak
- Support for OpenID Connect Discovery (`.well-known/openid-configuration`)
  - Handles up to 3 HTTP redirects and resolves relative `Location` headers
- JWKs fetching with in-memory caching and ETag validation
- RS256 JWT verification with `kid` matching
- Claim validation: `aud`, `iss`, `exp`, `nbf`
- Configurable via `discovery_url`, `audience`, and `skip_paths` options
  - `skip_paths` supports `/`, literal paths, and `*` wildcards (e.g. `/public/*`, `/rails/*`)
- Environment keys set by middleware:
  - `env["verikloak.user"]` for decoded claims
  - `env["verikloak.token"]` for the raw Bearer token
- Comprehensive RSpec test suite:
  - `TokenDecoder` unit tests
  - `Discovery` behavior (redirects, invalid JSON, required fields)
  - `JwksCache` behavior (ETag/304, parse/validation errors)
  - Rack middleware integration tests (401/503 mapping, header parsing)
- Docker-based development and CI-ready setup
- RuboCop static analysis configuration
- Structured error handling & responses:
  - Token/auth errors → **401 Unauthorized** with `WWW-Authenticate` header (RFC 6750)
  - Discovery/JWKs errors → **503 Service Unavailable**
  - Structured error codes: `invalid_token`, `expired_token`, `not_yet_valid`,
    `invalid_issuer`, `invalid_audience`, `unsupported_algorithm`,
    `jwks_fetch_failed`, `jwks_parse_failed`, `jwks_cache_miss`,
    `discovery_metadata_fetch_failed`, `discovery_metadata_invalid`,
    `discovery_redirect_error`
