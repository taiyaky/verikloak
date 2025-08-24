# frozen_string_literal: true

require 'rack'
require 'json'

module Verikloak
  # Internal helper mixin that encapsulates error-to-HTTP mapping logic
  # used by {Verikloak::Middleware}. By extracting this mapping into a
  # separate module, the middleware class remains shorter and easier to
  # reason about.
  #
  # This module does not depend on Rack internals; it only interprets
  # Verikloak error objects and their `code` attributes.
  #
  # @api private
  module MiddlewareErrorMapping
    # Set of token/client-side error codes that should map to **401 Unauthorized**.
    # @return [Array<String>]
    AUTH_ERROR_CODES = %w[
      invalid_token expired_token not_yet_valid invalid_issuer invalid_audience
      invalid_signature unsupported_algorithm missing_authorization_header invalid_authorization_header
    ].freeze

    # Set of middleware/infrastructure error codes that should map to **503 Service Unavailable**.
    # @return [Array<String>]
    INFRA_ERROR_CODES = %w[jwks_fetch_failed jwks_cache_miss].freeze

    # @param code [String, nil] short error code
    # @return [Boolean] true if the error should be treated as a 403 Forbidden
    def forbidden?(code)
      code == 'forbidden'
    end

    # @param code [String, nil]
    # @return [Boolean] true if the error belongs to {AUTH_ERROR_CODES}
    def auth_error?(code)
      code && AUTH_ERROR_CODES.include?(code)
    end

    # Maps dependency-layer errors to a pair of `[code, http_status]`.
    #
    # @param error [Exception]
    # @return [Array(String, Integer), nil] two-element tuple or nil when not applicable
    def dependency_error_tuple(error)
      if error.is_a?(Verikloak::DiscoveryError)
        [error.code || 'discovery_error', 503]
      elsif error.is_a?(Verikloak::JwksCacheError)
        [error.code || 'jwks_error', 503]
      end
    end

    # Maps middleware infrastructure errors to a pair of `[code, http_status]`.
    #
    # @param error [Exception]
    # @param code [String, nil]
    # @return [Array(String, Integer), nil]
    def infra_error_tuple(error, code)
      return unless error.is_a?(Verikloak::MiddlewareError) && code && INFRA_ERROR_CODES.include?(code)

      [code, 503]
    end

    # Final mapping fallback when no other rule has handled the error.
    #
    # @param error [Exception]
    # @param code [String, nil]
    # @return [Array(String, Integer)] two-element tuple
    def fallback_tuple(error, code)
      case error
      when Verikloak::TokenDecoderError
        ['invalid_token', 401]
      when Verikloak::MiddlewareError
        [code || 'invalid_token', 401]
      else
        ['internal_server_error', 500]
      end
    end
  end

  # Rack middleware that verifies incoming JWT access tokens (Keycloak) using
  # OpenID Connect discovery and JWKS. On success, it populates:
  #
  # * `env['verikloak.token']` — the raw JWT string
  # * `env['verikloak.user']`  — the decoded JWT claims Hash
  #
  # Failures are converted to JSON error responses with appropriate status codes.
  class Middleware
    # @param app [#call] downstream Rack app
    # @param discovery_url [String] OIDC discovery endpoint URL
    # @param audience [String] Expected `aud` claim
    # @param skip_paths [Array<String>] Literal paths or wildcard patterns to bypass auth
    # @param discovery [Discovery, nil] Custom discovery instance (for DI/tests)
    # @param jwks_cache [JwksCache, nil] Custom JWKS cache instance (for DI/tests)
    def initialize(app,
                   discovery_url:,
                   audience:,
                   skip_paths: [],
                   discovery: nil,
                   jwks_cache: nil)
      @app           = app
      @audience      = audience
      @skip_paths    = skip_paths
      @discovery     = discovery || Discovery.new(discovery_url: discovery_url)
      @jwks_cache    = jwks_cache
      @issuer        = nil
      @mutex         = Mutex.new
    end

    # Rack entrypoint.
    #
    # @param env [Hash] Rack environment
    # @return [Array(Integer, Hash, Array<String>)] standard Rack response
    def call(env)
      path = env['PATH_INFO']
      return @app.call(env) if skip?(path)

      token = extract_token(env)

      handle_request(env, token)
    rescue Verikloak::Error => e
      code, status = map_error(e)
      error_response(code, e.message, status)
    rescue StandardError => e
      log_internal_error(e)
      error_response('internal_server_error', 'An unexpected error occurred', 500)
    end

    private

    include MiddlewareErrorMapping

    # Determines whether a token verification failure warrants a one-time JWKS refresh
    # and retry (e.g., after key rotation).
    #
    # @param error [Exception]
    # @return [Boolean]
    # @api private
    def retryable_decoder_error?(error)
      return false unless error.is_a?(TokenDecoderError)

      return true if error.code == 'invalid_signature'
      return true if error.code == 'invalid_token' && error.message&.include?('Key with kid=')

      false
    end

    # Ensures JWKS are up-to-date by invoking {#ensure_jwks_cache!}.
    # Errors are not swallowed and are handled by the caller.
    #
    # @return [void]
    # @raise [Verikloak::DiscoveryError, Verikloak::JwksCacheError]
    # @api private
    def refresh_jwks!
      # Ensure discovery has been performed so we have a jwks_cache instance.
      ensure_jwks_cache!
    end

    # Checks whether the request path matches any skip pattern.
    #
    # Supported patterns:
    # * `'/'` — matches only the root path
    # * `'/foo/*'` — matches `/foo` itself and any nested path under it
    # * `'/api/public'` — exact match only (no wildcard)
    #
    # @param path [String]
    # @return [Boolean]
    def skip?(path)
      @skip_paths.any? do |pattern|
        if pattern == '/'
          path == '/'
        elsif pattern.end_with?('/*')
          prefix = pattern.chomp('/*')
          path == prefix || path.start_with?("#{prefix}/")
        else
          path == pattern || path.start_with?("#{pattern}/")
        end
      end
    end

    # Verifies the token, stores result in Rack env, and forwards to the downstream app.
    #
    # @param env [Hash]
    # @param token [String]
    # @return [Array(Integer, Hash, Array<String>)]
    def handle_request(env, token)
      claims = decode_token(token)
      env['verikloak.token'] = token
      env['verikloak.user']  = claims
      @app.call(env)
    end

    # Extracts the Bearer token from the `Authorization` header.
    #
    # @param env [Hash]
    # @return [String] the raw JWT string
    # @raise [Verikloak::MiddlewareError] when the header is missing or malformed
    def extract_token(env)
      auth = env['HTTP_AUTHORIZATION']
      if auth.to_s.strip.empty?
        raise MiddlewareError.new('Missing Authorization header',
                                  code: 'missing_authorization_header')
      end

      scheme, token = auth.split(' ', 2)
      unless scheme && token && scheme.casecmp('Bearer').zero?
        raise MiddlewareError.new('Invalid Authorization header format', code: 'invalid_authorization_header')
      end

      token
    end

    # Decodes and verifies the JWT using the cached JWKS. On certain verification
    # failures (e.g., key rotation), it refreshes the JWKS and retries once.
    #
    # @param token [String]
    # @return [Hash] decoded JWT claims
    # @raise [Verikloak::Error] bubbles up verification/fetch errors for centralized handling
    def decode_token(token)
      ensure_jwks_cache!
      if @jwks_cache.cached.nil? || @jwks_cache.cached.empty?
        raise MiddlewareError.new('JWKS cache is empty, cannot verify token', code: 'jwks_cache_miss')
      end

      # First attempt
      decoder = TokenDecoder.new(
        jwks: @jwks_cache.cached,
        issuer: @issuer,
        audience: @audience
      )

      begin
        decoder.decode!(token)
      rescue TokenDecoderError => e
        # On key rotation or signature mismatch, refresh JWKS and retry once.
        raise unless retryable_decoder_error?(e)

        refresh_jwks!

        # Rebuild decoder with refreshed keys and try once more.
        decoder = TokenDecoder.new(
          jwks: @jwks_cache.cached,
          issuer: @issuer,
          audience: @audience
        )
        decoder.decode!(token)
      end
    end

    # Ensures that discovery metadata and JWKS cache are initialized and up-to-date.
    # This method is thread-safe.
    #
    # * When the cache instance is missing, it is created from discovery metadata.
    # * JWKS are (re)fetched every time; ETag/Cache-Control headers minimize traffic.
    #
    # @return [void]
    # @raise [Verikloak::DiscoveryError, Verikloak::JwksCacheError, Verikloak::MiddlewareError]
    def ensure_jwks_cache!
      @mutex.synchronize do
        if @jwks_cache.nil?
          config   = @discovery.fetch!
          @issuer  = config['issuer']
          jwks_uri = config['jwks_uri']
          @jwks_cache = JwksCache.new(jwks_uri: jwks_uri)
        end

        @jwks_cache.fetch!
      end
    rescue Verikloak::DiscoveryError, Verikloak::JwksCacheError => e
      # Re-raise so that specific error codes can be mapped in the middleware
      raise e
    rescue StandardError => e
      raise MiddlewareError.new("Failed to initialize JWKS cache: #{e.message}", code: 'jwks_fetch_failed')
    end

    # Converts a raised error into a `[code, http_status]` tuple for response rendering.
    #
    # @param error [Exception]
    # @return [Array(String, Integer)]
    def map_error(error)
      code = error.respond_to?(:code) ? error.code : nil

      return [code, 403] if forbidden?(code)
      return [code, 401] if auth_error?(code)

      if (dep = dependency_error_tuple(error))
        return dep
      end

      if (infra = infra_error_tuple(error, code))
        return infra
      end

      fallback_tuple(error, code)
    end

    # Builds a JSON error response with RFC 6750 `WWW-Authenticate` header for 401.
    #
    # @param code [String]
    # @param message [String]
    # @param status [Integer]
    # @return [Array(Integer, Hash, Array<String>)] Rack response triple
    def error_response(code = 'unauthorized', message = 'Unauthorized', status = 401)
      body = { error: code, message: message }.to_json
      headers = { 'Content-Type' => 'application/json' }
      if status == 401
        headers['WWW-Authenticate'] =
          %(Bearer realm="verikloak", error="#{code}", error_description="#{message.gsub('"', '\\"')}")
      end
      [status, headers, [body]]
    end

    # Logs unexpected internal errors to STDERR (non-PII). Used for diagnostics only.
    #
    # @param error [Exception]
    # @return [void]
    # @api private
    def log_internal_error(error)
      warn "[verikloak] Internal error: #{error.class} - #{error.message}"
      warn error.backtrace.join("\n") if error.backtrace
    end
  end
end
