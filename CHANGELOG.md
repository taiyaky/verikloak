# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.2] - 2025-08-31

### Added
- Middleware: new `connection:` option to inject a Faraday::Connection, shared by Discovery and JWKs.
- Middleware: new `leeway:` and `token_verify_options:` options, delegated to TokenDecoder.
- README: documented usage of `connection`, leeway/options, and clarified `skip_paths` behavior.

### Changed
- Middleware: `skip_paths` semantics clarified — plain paths are exact-match only, use `/*` for prefix matching.
- Middleware: TokenDecoder instances are now cached per JWKs fetch for performance improvement.
- Internal: RuboCop style fixes (`HashExcept`, `HashTransformKeys`, long line splits).

---

## [0.1.1] - 2025-08-24

### Changed

- Updated dependency constraints in gemspec (`json` ~> 2.6, `jwt` ~> 2.7) for better compatibility control
- Updated README badges (Gem version, Ruby version, downloads)

---

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
