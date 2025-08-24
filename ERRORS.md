# Verikloak Error Catalog

⚠️ **Important Note**

This document is a *developer reference* reflecting the **actual behavior** of Verikloak as implemented today, including internal exception classes and how Rack middleware maps them to responses.


> **Response mapping (current)**
>
> - Exceptions inheriting from `Verikloak::Error` → mapped by type:
>   - Token / Authorization errors → **401 Unauthorized** with JSON and `WWW-Authenticate` header including `error` and `error_description`.
>   - Discovery / JWKS fetch/parse errors → **503 Service Unavailable** with JSON using split error codes:
>     - `jwks_fetch_failed` or `jwks_parse_failed`
>     - `discovery_metadata_fetch_failed` or `discovery_metadata_invalid`
> - Other unexpected exceptions (`StandardError`) → **500 Internal Server Error** with JSON `{"error":"internal_server_error","message":"An unexpected error occurred"}`
---

## General Response Format

All errors follow the same JSON format:

| Field    | Type   | Description                      |
|----------|--------|----------------------------------|
| error    | string | A short error code identifier    |
| message  | string | A descriptive error message      |
| details  | object | Optional additional error info   |

> Note: 401 responses now include detailed error codes (e.g., invalid_token, expired_token) and the WWW-Authenticate header carries both error and error_description per RFC 6750.

---

## TokenDecoderError

Raised during JWT verification (`Verikloak::TokenDecoder`).  
**HTTP Status:** 401 Unauthorized (via middleware, error code reflects the specific condition)

| JSON `error`           | `message` example                                            | When it happens |
|------------------------|-------------------------------------------------------------|----------------|
| `unsupported_algorithm`| `Missing or unsupported algorithm`                          | JWT header `alg` is not `RS256` or missing |
| `invalid_token`        | `JWT header missing 'kid'`                                  | JWT header has no `kid` |
| `invalid_token`        | `Key with kid=<kid> not found in JWKS`                      | No matching JWK by `kid` |
| `invalid_token`        | `Unsupported key type '<kty>'. Only RSA is supported`       | Non-RSA JWK |
| `invalid_token`        | `Failed to import JWK: <detail>`                            | RSA key import failed |
| `expired_token`        | `Token has expired`                                         | `JWT::ExpiredSignature` |
| `not_yet_valid`        | `Token is not yet valid (nbf in the future)`                | `JWT::ImmatureSignature` |
| `invalid_issuer`       | `Invalid issuer (iss claim)`                                | `JWT::InvalidIssuerError` |
| `invalid_audience`     | `Invalid audience (aud claim)`                              | `JWT::InvalidAudError` |
| `invalid_token`        | `Invalid issued-at (iat) claim`                             | `JWT::InvalidIatError` |
| `invalid_token`        | `JWT decode failed: <detail>`                               | `JWT::DecodeError` |
| `invalid_token`        | `Unexpected token verification error: <detail>`             | Any other error while decoding |

---

## DiscoveryError and JwksCacheError

Errors raised during fetching or parsing of the OIDC discovery document or JWKS are wrapped and surfaced as 503 Service Unavailable by the middleware.

| JSON `error`                  | `message` example                                   |
|------------------------------|-----------------------------------------------------|
| `jwks_fetch_failed`           | `Failed to fetch JWKS: Net::ReadTimeout`            |
| `jwks_parse_failed`           | `Failed to parse JWKS: JSON::ParserError`           |
| `discovery_metadata_fetch_failed` | `Failed to fetch discovery document: 404 Not Found` |
| `discovery_metadata_invalid`  | `Failed to parse discovery document: unexpected format` |
| `discovery_redirect_error`    | `Redirect without Location header`, `Too many redirects (max 3)`, or `Redirect Location is invalid: ...` |

---

## MiddlewareError

Raised directly by the middleware in certain conditions.  
**HTTP Status:** 401 Unauthorized for client-side errors (e.g., Authorization header issues), 503 Service Unavailable for infrastructure issues (e.g., JWKS cache miss).

| JSON `error`              | `message` example                                  |
|---------------------------|----------------------------------------------------|
| `missing_authorization_header` | `Missing Authorization header`                   |
| `invalid_authorization_header` | `Invalid Authorization header format`            |
| `jwks_cache_miss`         | `JWKS cache is empty, cannot verify token`         |

---

## Generic Errors

**Missing Authorization header**

- **HTTP:** 401 Unauthorized  
- **JSON:** `{"error":"missing_authorization_header","message":"Missing Authorization header"}`

**Invalid Authorization header format**

- **HTTP:** 401 Unauthorized  
- **JSON:** `{"error":"invalid_authorization_header","message":"Invalid Authorization header format"}`

**Unexpected StandardError**

- **HTTP:** 500 Internal Server Error  
- **JSON:** `{"error":"internal_server_error","message":"An unexpected error occurred"}`

---

## Notes & Future Direction

- This document reflects the **current implementation** of Verikloak error handling.
- The README contains the **intended public error specification** with structured error codes.
- Future versions of Verikloak aim to align implementation with the README specification, but current implementation already provides structured error codes and enriched WWW-Authenticate headers.