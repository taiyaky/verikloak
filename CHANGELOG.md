# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-07-03

### Changed
- **JWKs revalidation is now throttled on the request path** (`Middleware`): previously every request synchronized on a single mutex and called `JwksCache#fetch!`, so identity providers that do not send `Cache-Control: max-age` on their JWKs endpoint (including Keycloak's default) caused a conditional HTTP GET — with retries and timeouts — inside the lock on **every** request. The middleware now revalidates at most once per `jwks_refresh_interval` seconds (default `60`) and serves requests within the window lock-free from the in-memory key set. Key rotation is not delayed: an unknown `kid` or signature mismatch forces an immediate refresh and one retry, exactly as before. Pass `jwks_refresh_interval: 0` to restore the previous revalidate-on-every-request behavior.
- **Decoder cache is now keyed and invalidated by JWKs content** (`Middleware`): rotation detection previously compared the cached key array's object identity (`__id__`), so any `200 OK` refresh — even one returning identical keys — purged all cached `TokenDecoder` instances and rebuilt them, and object-id recycling could in principle miss a rotation. The cache key and the purge check now use a SHA-256 digest of the key set content, so content-identical refreshes keep the cache warm and rotations are detected reliably.
- **`kid_not_found` error code** (`TokenDecoder`): an unknown `kid` now raises `TokenDecoderError` with code `kid_not_found` instead of `invalid_token`, and the middleware's refresh-and-retry trigger matches on that code instead of sniffing the error message. HTTP responses are unchanged (still `401` with JSON `error: "invalid_token"`); only `error.code` seen by callers rescuing `Verikloak::TokenDecoderError` directly changes.

### Security
- **Bumped `jwt` to `3.2.0` and `faraday` to `2.14.3`** in `Gemfile.lock` to clear advisories surfaced by `bundler-audit`: CVE-2026-45363 (jwt: HS256 verification accepts an empty HMAC key — verikloak itself is unaffected as it pins RS256 with RSA keys) and the faraday nested-query-string DoS (GHSA-98m9-hrrm-r99r, fixed in 2.14.3).
- **Minimum `faraday` runtime dependency raised to `2.14.3`** (gemspec): the `>= 2.14.1` floor was introduced for CVE-2026-25765, but per GHSA-5rv5-xj5j-3484 that fix was incomplete (protocol-relative URIs could still bypass host scoping, completed in 2.14.2), and 2.14.3 additionally fixes the nested-query-string DoS above. The jwt range is intentionally left at `>= 2.7, < 4.0`: only 3.0.0–3.1.x are affected by CVE-2026-45363, jwt 2.x is not, and verikloak's own verification path pins RS256 with RSA keys.
- **Response size limits**: discovery and JWKs response bodies larger than 1 MB (`Verikloak::HTTP::MAX_RESPONSE_BYTES`) are rejected (`discovery_metadata_invalid` / `jwks_parse_failed`) before JSON parsing, preventing a compromised endpoint from exhausting memory.
- **`kid` truncation in error messages** (`TokenDecoder`): the attacker-controlled `kid` value echoed in "Key with kid=... not found" messages (and therefore in 401 response bodies and `WWW-Authenticate` headers) is truncated to 64 characters.
- **DNS rebinding limitation documented** (SECURITY.md): the SSRF checks resolve hostnames at validation time while the HTTP client resolves them again at connection time; the gap and recommended mitigations are now documented.

### Added
- **`jwks_refresh_interval` middleware option** (default `60`): minimum seconds between JWKs revalidations on the request path.
- **`Verikloak::SafeUrl`** (internal): shared URL normalization, HTTPS-enforcement, and private-IP resolution helpers previously duplicated between `Discovery` and `JwksCache`. `Verikloak::PRIVATE_IP_RANGES` is unchanged and now lives alongside it.
- **CI compatibility matrix**: the suite now also runs on Ruby 3.1, 3.2, and 3.3 (via `gemfiles/compat.gemfile`), backing the gemspec's `required_ruby_version >= 3.1` claim; the docker-based job continues to cover 3.4.
- **Coverage gate**: SimpleCov now runs in CI (`SIMPLECOV=true`) and fails the suite below 90% line coverage (currently ~95%).

### Fixed
- **Key-rotation retry now bypasses `Cache-Control: max-age` freshness** (`JwksCache#force_fetch!`): when a token failed with an unknown `kid` or bad signature, the forced JWKs refresh previously called plain `fetch!`, which returns the cached keys without any HTTP request while `max-age` is still fresh — so on IdPs that send `max-age` on the JWKs endpoint, tokens signed with rotated keys kept failing until the TTL expired (pre-existing behavior, surfaced by the throttling work). The retry path now revalidates over HTTP unconditionally; the ETag conditional request still applies, so an unchanged key set costs only a 304. Injected caches that only implement `fetch!` keep their previous behavior.
- **CI: the SimpleCov coverage gate now actually runs in the docker job**: the step-level `SIMPLECOV=true` env var stayed on the Actions runner shell and never reached the Compose container, so `ENV['SIMPLECOV']` was unset and the 90% gate silently did not run. The workflow now forwards it with `docker compose run -e SIMPLECOV`.
- **Audience callable arity fallback no longer swallows application errors**: the retry-on-`ArgumentError` fallback now only matches messages *starting with* `wrong number of arguments`, so an `ArgumentError` raised inside the callable body that merely mentions the phrase propagates instead of triggering a second invocation.
- **README**: removed the misleading `algorithms:` override example — the token header is validated to be exactly `RS256` before decoding regardless of that option; documented the constraint instead.

---

## [1.0.2] - 2026-05-09

### Fixed
- **`iat` claim now honors `leeway`** (`TokenDecoder`): On ruby-jwt 3.x the built-in `Claims::IssuedAt` validator ignores the `leeway` option and raises `JWT::InvalidIatError` whenever `iat` is even a fraction of a second in the future. In typical OIDC deployments the IdP (e.g. Keycloak) and the Resource Server run on different hosts/containers, so `iat` is routinely a few hundred milliseconds to a few seconds ahead of the Resource Server's clock and the previously-effective leeway of `0` for `iat` produced spurious 401s. `TokenDecoder` now disables ruby-jwt's built-in `iat` check and performs its own `iat` validation that applies the configured `leeway` consistently with `exp` and `nbf`. Behaviour for tokens with `iat` further in the future than `leeway` is unchanged (still rejected with `invalid_token`). Pass `options: { verify_iat: false }` to skip the check entirely.
- **`iat` validation now handles symbol-keyed payloads**: `verify_iat_with_leeway!` looks up both `'iat'` and `:iat`, so callers who request symbol-keyed payloads from `JWT.decode` still get the leeway-aware `iat` check applied.

### Security
- **Bumped `rack` to `>= 3.2.6` and `json` to `>= 2.19.5`** in `Gemfile.lock` to clear known advisories surfaced by `bundler-audit` (rack request-smuggling and json format-string injection).

---

## [1.0.1] - 2026-02-15

### Fixed
- **SSRF protection bypass for development mode**: `allow_http: true` now also skips private IP validation in both `JwksCache` (initial `jwks_uri` resolution) and `Discovery` (redirect target resolution). Previously, even with `allow_http: true`, connections to Keycloak on private/loopback IPs (e.g. `127.0.0.1`, `10.x.x.x`, `192.168.x.x`) were blocked by SSRF protection, making local development impossible.
- **Inconsistent SSRF behaviour**: `Discovery#fetch!` did not validate the initial discovery URL against private IPs (only redirect targets), while `JwksCache` unconditionally blocked private IPs at initialisation. Both now consistently skip private IP checks when `allow_http: true`.

---

## [1.0.0] - 2026-02-15

### Security
- **JWKs URI SSRF protection**: `JwksCache` now validates `jwks_uri` from discovery documents against private IP ranges (RFC 1918, loopback, link-local), preventing a malicious discovery endpoint from directing JWKs fetches to internal services

### Fixed
- **`TokenDecoder` error classification**: `invalid_signature` and `unsupported_algorithm` error codes were never returned due to dead `case/when` branches — replaced with `if/elsif` chain so `JWT::VerificationError` and `JWT::IncorrectAlgorithm` are classified correctly

### Added
- **`rack` runtime dependency**: Added `rack >= 2.2, < 4.0` to gemspec (was previously required but undeclared)

### Changed
- **`json` dependency relaxed**: `~> 2.18` → `~> 2.6` to broaden compatibility with older Ruby versions and bundled json gems
- **v1.0.0 stable release**: Public API is now considered stable under Semantic Versioning

---

## [0.4.1] - 2026-02-15

### Added
- `Verikloak::SkipPathMatcher` now supports `Regexp` patterns alongside string paths, restoring compatibility with `verikloak-audience` skip_paths Regexp usage

---

## [0.4.0] - 2026-02-15

### Security
- **CVE-2026-25765**: Bump `faraday` runtime dependency to `>= 2.14.1`
- **Header injection**: Sanitize CR/LF characters in `WWW-Authenticate` header values via `Verikloak::ErrorResponse`
- **JWT size limit**: Reject tokens exceeding 8 KB (`MAX_TOKEN_BYTES = 8192`) to mitigate denial-of-service
- **HTTPS enforcement**: `Discovery` and `JwksCache` now reject `http://` URLs unless `allow_http: true` is explicitly set
- **HTTPS redirect enforcement**: Redirect targets during OIDC discovery are now scheme-checked — plain HTTP redirects are blocked unless `allow_http: true`, and non-HTTP(S) schemes (e.g. `ftp://`) are always rejected
- **SSRF protection**: Redirect targets in OIDC discovery are validated against private IP ranges (RFC 1918, loopback, link-local)
- **IPv4-mapped IPv6 SSRF hardening**: IPv4-mapped IPv6 addresses (e.g. `::ffff:127.0.0.1`) are normalised to native IPv4 before private-range checks, preventing bypass via mapped addresses
- **URL normalisation**: `Discovery` and `JwksCache` now strip leading/trailing whitespace from URLs during initialisation, ensuring the validated URL matches what is used for HTTP requests

### Added
- `Verikloak::ErrorResponse` — shared RFC 6750-compliant JSON error response builder
- `Verikloak::SkipPathMatcher` — extracted reusable skip-path matching module
- `Verikloak::Error#http_status` attribute for structured error hierarchy
- `allow_http:` option on `Middleware`, `Discovery`, and `JwksCache`

### Changed
- **BREAKING**: Minimum `faraday` version raised to `2.14.1`
- **BREAKING**: Minimum `faraday-retry` version raised to `2.4.0`
- Runtime dependency `json` added (`~> 2.18`)
- Dev dependency `rspec` pinned to `~> 3.13`, `rubocop-rspec` pinned to `~> 3.9`, `webmock` pinned to `~> 3.26`

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
