# Verikloak

[![CI](https://github.com/taiyaky/verikloak/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/taiyaky/verikloak/actions/workflows/ci.yml)
[![Gem Version](https://img.shields.io/gem/v/verikloak)](https://rubygems.org/gems/verikloak)
![Ruby Version](https://img.shields.io/gem/rt/ruby/verikloak)
[![Downloads](https://img.shields.io/gem/dt/verikloak)](https://rubygems.org/gems/verikloak)

A lightweight Rack middleware for verifying Keycloak JWT access tokens via OpenID Connect.

Verikloak is a plug-and-play solution for Ruby (especially Rails API) apps that need to validate incoming `Bearer` tokens issued by Keycloak. It uses OpenID Connect Discovery and JWKS to fetch the public keys and verify JWT signatures securely.

---

## Features

- OpenID Connect Discovery (`.well-known/openid-configuration`)
- JWKs auto-fetch and in-memory caching with ETag support
- RS256 JWT verification using `kid`
- `aud`, `iss`, `exp`, `nbf` claim validation
- Rails/Rack middleware support
- Faraday-based customizable HTTP layer

---

## Installation

Add this line to your application's `Gemfile`:

```ruby
gem "verikloak"
```

Then install:

```bash
bundle install
```

---

## Usage

### Rails (API mode)

Add the middleware in `config/application.rb`:

```ruby
config.middleware.use Verikloak::Middleware,
  discovery_url: "https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration",
  audience: "your-client-id",
  skip_paths: ['/skip_path']
```

#### Handling Authentication Failures

By default, invalid or missing tokens will raise a `Verikloak::Errors::InvalidToken` error.  
In a Rails app, you can rescue this globally and return a consistent JSON response:

```ruby
class ApplicationController < ActionController::API
  rescue_from Verikloak::Errors::InvalidToken do |e|
    render json: { error: e.message }, status: :unauthorized
  end
end
```

This ensures clients always receive a structured `401 Unauthorized` response.

---

#### Recommended: use environment variables in production

```ruby
config.middleware.use Verikloak::Middleware,
  discovery_url: ENV.fetch("DISCOVERY_URL"),
  audience: ENV.fetch("CLIENT_ID"),
  skip_paths: ['/', '/health', '/public/*', '/rails/*']
```
#### In production, set these variables in your environment for security and flexibility.

This makes the configuration secure and flexible across environments.

```ruby
request.env["verikloak.user"]  # => JWT claims hash
request.env["verikloak.token"] # => Raw JWT string
```
---
### Accessing claims in controllers

Once the middleware is enabled, Verikloak adds the decoded token and raw JWT to the Rack environment.  
You can access them in any Rails controller:

```ruby
class Api::V1::NotesController < ApplicationController
  def index
    user_claims = request.env["verikloak.user"]    # Hash of decoded Keycloak JWT claims
    token       = request.env["verikloak.token"]   # Raw JWT token string
    
    # Example: use claims for authorization or logging
    render json: { sub: user_claims["sub"], email: user_claims["email"] }
  end
end
```
---
### Standalone Rack app

```ruby
# config.ru example for a standalone Rack app
require "verikloak"

use Verikloak::Middleware,
  discovery_url: "https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration",
  audience: "my-client-id"

run ->(env) {
  user = env["verikloak.user"] # Decoded JWT claims hash (if token is valid)
  [200, { "Content-Type" => "application/json" }, [user.to_json]]
}
```
---

## How It Works

1. Extracts the `Authorization: Bearer <token>` header
2. Fetches the OIDC discovery document (only once or when expired)
3. Downloads JWKS public keys from the provided `jwks_uri`
4. Matches the `kid` from JWT header to select the right JWK
5. Decodes and verifies the JWT using `RS256`
6. Validates the following claims:
   - `aud` (audience)
   - `iss` (issuer)
   - `exp` (expiration)
   - `nbf` (not before)
7. Makes the decoded payload available in `env["verikloak.user"]`

---

## Error Responses

Verikloak returns JSON error responses in a consistent format with structured error codes. The HTTP status code reflects the nature of the error: 401 for client-side authentication issues, 503 for server-side discovery/JWKS errors, and 500 for unexpected internal errors.

### Common HTTP Responses

- `401 Unauthorized`: The access token is missing, invalid, expired, or otherwise not valid.
- `503 Service Unavailable`: Discovery or JWKS fetch/parsing failed (server-side issue).
- `500 Internal Server Error`: An unexpected error occurred.

### Representative Examples

```json
{
  "error": "invalid_token",
  "message": "The access token is missing or invalid"
}
```

```json
{
  "error": "expired_token",
  "message": "The access token has expired"
}
```

```json
{
  "error": "jwks_fetch_failed",
  "message": "Failed to fetch JWKS keys"
}
```

```json
{
  "error": "jwks_parse_failed",
  "message": "Failed to parse JWKS keys"
}
```

```json
{
  "error": "discovery_metadata_fetch_failed",
  "message": "Failed to fetch OIDC discovery document"
}
```

```json
{
  "error": "discovery_metadata_invalid",
  "message": "Failed to parse OIDC discovery document"
}
```

### Error Types

| Error Code                 | HTTP Status               | Description                                                                                   |
|----------------------------|---------------------------|-----------------------------------------------------------------------------------------------|
| `invalid_token`            | 401 Unauthorized          | The token is missing, malformed, or invalid                                                  |
| `expired_token`            | 401 Unauthorized          | The token has expired                                                                        |
| `missing_authorization_header` | 401 Unauthorized      | The `Authorization` header is missing                                                        |
| `invalid_authorization_header` | 401 Unauthorized      | The `Authorization` header format is invalid                                                 |
| `unsupported_algorithm`    | 401 Unauthorized          | The token’s signing algorithm is not supported                                               |
| `invalid_signature`        | 401 Unauthorized          | The token signature could not be verified                                                    |
| `invalid_issuer`           | 401 Unauthorized          | Invalid `iss` claim                                                                          |
| `invalid_audience`         | 401 Unauthorized          | Invalid `aud` claim                                                                          |
| `not_yet_valid`            | 401 Unauthorized          | The token is not yet valid (`nbf` in the future)                                             |
| `jwks_fetch_failed`        | 503 Service Unavailable   | Failed to fetch JWKS keys                                                                    |
| `jwks_parse_failed`        | 503 Service Unavailable   | Failed to parse JWKS keys                                                                    |
| `jwks_cache_miss`          | 503 Service Unavailable   | JWKS cache is empty (e.g., 304 Not Modified without prior cache)                             |
| `discovery_metadata_fetch_failed` | 503 Service Unavailable   | Failed to fetch OIDC discovery document                                               |
| `discovery_metadata_invalid` | 503 Service Unavailable   | Failed to parse OIDC discovery document                                                    |
| `discovery_redirect_error` | 503 Service Unavailable   | Discovery response was a redirect without a valid Location header                           |
| `internal_server_error`    | 500 Internal Server Error | Unexpected internal error (catch-all)                                                        |

> Note: The `decode_with_public_key` method ensures consistent error codes for all JWT verification failures.  
> It may raise `invalid_signature`, `unsupported_algorithm`, `expired_token`, `invalid_issuer`, `invalid_audience`, or `not_yet_valid` depending on the verification outcome.

For a full list of error cases and detailed explanations, please see the [ERRORS.md](ERRORS.md) file.

## Configuration Options

| Key             | Required | Description                                 |
| --------------- | -------- | ------------------------------------------- |
| `discovery_url` | Yes   | Full URL to your realm's OIDC discovery doc |
| `audience`      | Yes   | Your client ID (checked against `aud`)      |
| `skip_paths`    | No       | Array of paths or wildcards to skip authentication, e.g. `['/', '/health', '/public/*']`. **Note:** Regex patterns are not supported. |
| `discovery`     | No       | Inject custom Discovery instance (advanced/testing) |
| `jwks_cache`    | No       | Inject custom JwksCache instance (advanced/testing) |

#### Option: `skip_paths`

`skip_paths` lets you specify paths (or wildcard patterns) where authentication should be **skipped**.  
For example:

```ruby
skip_paths: ['/', '/health', '/public/*', '/rails/*']
```
- `'/'` matches only the root path.
- `'/foo/*'` matches `/foo` and any subpath like `/foo/bar` or `/foo/bar/baz`.
- `'/api/public'` matches **only** `/api/public` (for subpaths, use `'/api/public/*'`).
- `'/rails/*'` matches `/rails` itself as well as `/rails/foo`, `/rails/foo/bar`, etc.

Paths **not matched** by any `skip_paths` entry will require a valid JWT.

**Note:** Regex patterns are not supported. Only literal paths and `*` wildcards are allowed.  
Internally, `*` expands to match nested paths, so patterns like `/rails/*` are valid. This differs from regex — for example, `'/rails'` alone matches only `/rails`, while `'/rails/*'` covers both `/rails` and deeper subpaths.

---

## Architecture

Verikloak consists of modular components, each with a focused responsibility:

| Component       | Responsibility                                        | Layer        |
|----------------|--------------------------------------------------------|--------------|
| `Middleware`    | Rack-compatible entry point for token validation     | Rack layer   |
| `Discovery`     | Fetches OIDC discovery metadata (`.well-known`)      | Network layer|
| `JwksCache`     | Fetches & caches JWKS public keys (with ETag)        | Cache layer  |
| `TokenDecoder`  | Decodes and verifies JWTs (signature, exp, nbf, iss, aud) | Crypto layer |
| `Errors`        | Centralized error hierarchy                          | Core layer   |

This separation enables better testing, modular reuse, and flexibility.

---

## Development (for contributors)

Clone and install dependencies:

```bash
git clone https://github.com/taiyaky/verikloak.git
cd verikloak
bundle install
```
See **Testing** below to run specs and RuboCop. For releasing, see **Publishing**.

---

## Testing

All pull requests and pushes are automatically tested with [RSpec](https://rspec.info/) and [RuboCop](https://rubocop.org/) via GitHub Actions.
See the CI badge at the top for current build status.

To run the test suite locally:

```bash
docker compose run --rm dev rspec
docker compose run --rm dev rubocop
```
---

## Contributing

Bug reports and pull requests are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Security

If you find a security vulnerability, please follow the instructions in [SECURITY.md](SECURITY.md).

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Publishing (for maintainers)

Gem release instructions are documented separately in [MAINTAINERS.md](MAINTAINERS.md).

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## References

- [OpenID Connect Discovery 1.0 Spec](https://openid.net/specs/openid-connect-discovery-1_0.html)  
- [Keycloak Documentation: Securing Apps](https://www.keycloak.org/docs/latest/securing_apps/#openid-connect)  
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) 