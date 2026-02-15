# frozen_string_literal: true

module Verikloak
  # Base error class for all Verikloak-related exceptions.
  #
  # All errors raised by this library inherit from this class so they can be
  # rescued in a consistent way. Each error may carry a short, programmatic
  # `code` (e.g., "invalid_token", "jwks_fetch_failed") that middleware and
  # callers can use to map to HTTP statuses or telemetry.
  #
  # @attr_reader [String, Symbol, nil] code
  #   A short error code identifier suitable for programmatic handling.
  # @attr_reader [Integer, nil] http_status
  #   HTTP status code associated with the error (e.g. 401, 403, 500, 503).
  #
  # @example Raising with a code
  #   raise Verikloak::Error.new("Something went wrong", code: "internal_error")
  # @example Raising with a code and HTTP status
  #   raise Verikloak::Error.new("Forbidden", code: "forbidden", http_status: 403)
  class Error < StandardError
    attr_reader :code, :http_status

    # @param message [String, nil] Human-readable error message.
    # @param code [String, Symbol, nil] Optional short error code for programmatic handling.
    # @param http_status [Integer, nil] Optional HTTP status code.
    def initialize(message = nil, code: nil, http_status: nil)
      super(message)
      @code = code
      @http_status = http_status
    end
  end

  # Raised when discovery document fetching or validation fails.
  #
  # Typical causes include network failures, non-200 responses, invalid JSON,
  # missing required fields (e.g., `jwks_uri`, `issuer`), or redirect issues.
  #
  # @see Verikloak::Discovery
  # @raise [DiscoveryError] from {Verikloak::Discovery#fetch!}
  class DiscoveryError < Error; end

  # Raised for middleware-level failures while processing a Rack request.
  #
  # Examples include missing/invalid Authorization headers, JWKs cache
  # initialization failures, or infrastructure issues detected by the
  # middleware itself.
  #
  # @see Verikloak::Middleware
  class MiddlewareError < Error; end

  # Raised when JWT token verification fails or the token is invalid.
  #
  # Common causes:
  # - Invalid or unsupported algorithm
  # - Invalid signature
  # - Expired (`exp`) or not-yet-valid (`nbf`) token
  # - Invalid `iss` / `aud` claims
  # - Malformed token structure or decode failures
  #
  # @see Verikloak::TokenDecoder
  # @raise [TokenDecoderError] from {Verikloak::TokenDecoder#decode!}
  class TokenDecoderError < Error; end

  # Raised when JWKs fetching, validation, or cache handling fails.
  #
  # Causes include HTTP failures, invalid JSON, missing required JWK fields,
  # or receiving 304 Not Modified without a prior cached value.
  #
  # @see Verikloak::JwksCache
  # @raise [JwksCacheError] from {Verikloak::JwksCache#fetch!}
  class JwksCacheError < Error; end
end
