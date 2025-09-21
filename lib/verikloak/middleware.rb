# frozen_string_literal: true

require 'rack'
require 'json'
require 'set'
require 'faraday'

require 'verikloak/http'

module Verikloak
  # @api private
  #
  # Internal mixin for skip-path normalization and matching.
  # Extracted from Middleware to reduce class length and improve testability.
  module SkipPathMatcher
    private

    # Checks whether the request path matches any compiled skip pattern.
    #
    # Supported patterns:
    # * `'/'`           — matches only the root path
    # * `'/foo'`        — exact-match only (matches `/foo` but **not** `/foo/...`)
    # * `'/foo/*'`      — prefix match (matches `/foo` and any nested path under it)
    #
    # @param path [String]
    # @return [Boolean]
    def skip?(path)
      np = normalize_path(path)
      return true if @skip_root && np == '/'
      return true if @skip_exacts.include?(np)

      @skip_prefixes.any? { |prefix| np == prefix || np.start_with?("#{prefix}/") }
    end

    # Normalizes paths for stable comparisons:
    # - ensures leading slash
    # - collapses multiple slashes (e.g. //foo///bar -> /foo/bar)
    # - removes trailing slash except for root
    #
    # @param path [String, nil]
    # @return [String]
    def normalize_path(path)
      s = (path || '').to_s
      s = "/#{s}" unless s.start_with?('/')
      s = s.gsub(%r{/+}, '/')
      s.length > 1 ? s.chomp('/') : s
    end

    # Pre-compiles {skip_paths} into fast lookup structures.
    #
    # * `@skip_root` — whether `'/'` is present
    # * `@skip_exacts` — exact-match set (e.g. `'/health'`)
    # * `@skip_prefixes` — wildcard prefixes for `'/*'` (e.g. `'/public'`)
    #
    # @param paths [Array<String>]
    # @return [void]
    def compile_skip_paths(paths)
      @skip_root     = false
      @skip_exacts   = Set.new
      @skip_prefixes = []

      Array(paths).each do |raw|
        next if raw.nil?

        s = raw.to_s.strip
        next if s.empty?

        if s == '/'
          @skip_root = true
          next
        end

        if s.end_with?('/*')
          prefix = normalize_path(s.chomp('/*'))
          next if prefix == '/' # root is handled by @skip_root

          @skip_prefixes << prefix
        else
          exact = normalize_path(s)
          @skip_exacts << exact
          # Do NOT add to @skip_prefixes here; plain '/foo' is exact-match only.
        end
      end

      @skip_prefixes.uniq!
    end
  end

  # @api private
  #
  # Internal mixin for JWT verification and discovery/JWKs management.
  # Extracted from Middleware to reduce class length and improve clarity.
  module MiddlewareTokenVerification
    private

    # Determines whether a token verification failure warrants a one-time JWKs refresh
    # and retry (e.g., after key rotation).
    #
    # @param error [Exception]
    # @return [Boolean]
    def retryable_decoder_error?(error)
      return false unless error.is_a?(TokenDecoderError)
      return true if error.code == 'invalid_signature'
      return true if error.code == 'invalid_token' && error.message&.include?('Key with kid=')

      false
    end

    # Returns a cached TokenDecoder instance for current inputs.
    # Cache key uses issuer, audience, leeway, token_verify_options, and JWKs fetched_at timestamp.
    def decoder_for(audience)
      keys = @jwks_cache.cached
      fetched_at = @jwks_cache.respond_to?(:fetched_at) ? @jwks_cache.fetched_at : nil
      cache_key = [
        @issuer,
        audience,
        @leeway,
        @token_verify_options,
        fetched_at
      ].hash
      @mutex.synchronize do
        @decoder_cache[cache_key] ||= TokenDecoder.new(
          jwks: keys,
          issuer: @issuer,
          audience: audience,
          leeway: @leeway,
          options: @token_verify_options
        )
      end
    end

    # Ensures JWKs are up-to-date by invoking {#ensure_jwks_cache!}.
    # Errors are not swallowed and are handled by the caller.
    #
    # @return [void]
    # @raise [Verikloak::DiscoveryError, Verikloak::JwksCacheError]
    def refresh_jwks!
      ensure_jwks_cache!
    end

    # Decodes and verifies the JWT using the cached JWKs. On certain verification
    # failures (e.g., key rotation), it refreshes the JWKs and retries once.
    #
    # @param token [String]
    # @return [Hash] decoded JWT claims
    # @raise [Verikloak::Error] bubbles up verification/fetch errors for centralized handling
    def decode_token(env, token)
      ensure_jwks_cache!
      if @jwks_cache.cached.nil? || @jwks_cache.cached.empty?
        raise MiddlewareError.new('JWKs cache is empty, cannot verify token', code: 'jwks_cache_miss')
      end

      audience = resolve_audience(env)

      # First attempt
      decoder = decoder_for(audience)

      begin
        decoder.decode!(token)
      rescue TokenDecoderError => e
        # On key rotation or signature mismatch, refresh JWKs and retry once.
        raise unless retryable_decoder_error?(e)

        refresh_jwks!

        # Rebuild decoder with refreshed keys and try once more.
        decoder = decoder_for(audience)
        decoder.decode!(token)
      end
    end

    # Resolves the expected audience for the current request.
    #
    # @param env [Hash] Rack environment.
    # @return [String, Array<String>] The expected audience value.
    # @raise [MiddlewareError] when the resolved audience is blank.
    def resolve_audience(env)
      source = @audience_source
      value = if source.respond_to?(:call)
                callable = source
                arity = callable.respond_to?(:arity) ? callable.arity : safe_callable_arity(callable)
                call_with_optional_env(callable, env, arity)
              else
                source
              end

      raise MiddlewareError.new('Audience is blank for the request', code: 'invalid_audience') if value.nil?

      if value.is_a?(Array)
        raise MiddlewareError.new('Audience is blank for the request', code: 'invalid_audience') if value.empty?

        return value
      end

      normalized = value.to_s
      raise MiddlewareError.new('Audience is blank for the request', code: 'invalid_audience') if normalized.empty?

      normalized
    end

    # Invokes the audience callable, passing the Rack env only when required.
    # Falls back to a zero-argument invocation if the callable raises
    # `ArgumentError` due to an unexpected argument.
    #
    # @param callable [#call] Audience resolver callable.
    # @param env [Hash] Rack environment.
    # @param arity [Integer, nil] Callable arity when known, nil otherwise.
    # @return [Object] Audience value returned by the callable.
    # @raise [ArgumentError] when the callable raises for reasons other than arity mismatch.
    def call_with_optional_env(callable, env, arity)
      return callable.call if arity&.zero?

      callable.call(env)
    rescue ArgumentError => e
      raise unless arity.nil? && wrong_arity_error?(e)

      callable.call
    end

    # Safely obtains a callable's arity, returning nil when `#method(:call)`
    # cannot be resolved (e.g., BasicObject-based objects).
    #
    # @param callable [#call]
    # @return [Integer, nil]
    def safe_callable_arity(callable)
      callable.method(:call).arity
    rescue NameError
      nil
    end

    # Returns true when the ArgumentError message indicates a wrong arity.
    #
    # @param error [ArgumentError]
    # @return [Boolean]
    def wrong_arity_error?(error)
      error.message.include?('wrong number of arguments')
    end

    # Ensures that discovery metadata and JWKs cache are initialized and up-to-date.
    # This method is thread-safe.
    #
    # * When the cache instance is missing, it is created from discovery metadata.
    # * JWKs are (re)fetched every time; ETag/Cache-Control headers minimize traffic.
    #
    # @return [void]
    # @raise [Verikloak::DiscoveryError, Verikloak::JwksCacheError, Verikloak::MiddlewareError]
    def ensure_jwks_cache!
      @mutex.synchronize do
        if @jwks_cache.nil?
          config   = @discovery.fetch!
          @issuer  = config['issuer']
          jwks_uri = config['jwks_uri']
          @jwks_cache = JwksCache.new(jwks_uri: jwks_uri, connection: @connection)
        end

        @jwks_cache.fetch!
      end
    rescue Verikloak::DiscoveryError, Verikloak::JwksCacheError => e
      # Re-raise so that specific error codes can be mapped in the middleware
      raise e
    rescue StandardError => e
      raise MiddlewareError.new("Failed to initialize JWKs cache: #{e.message}", code: 'jwks_fetch_failed')
    end
  end

  # @api private
  #
  # Internal mixin that encapsulates error-to-HTTP mapping logic used by
  # {Verikloak::Middleware}. By extracting this mapping into a separate module,
  # the middleware class stays concise and easier to reason about.
  #
  # This module does not depend on Rack internals; it only interprets
  # Verikloak error objects and their `code` attributes.
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

    private

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
  # OpenID Connect discovery and JWKs. On success, it populates:
  #
  # * `env['verikloak.token']` — the raw JWT string
  # * `env['verikloak.user']`  — the decoded JWT claims Hash
  #
  # Failures are converted to JSON error responses with appropriate status codes.
  class Middleware
    include MiddlewareErrorMapping
    include SkipPathMatcher
    include MiddlewareTokenVerification

    DEFAULT_REALM = 'verikloak'
    DEFAULT_TOKEN_ENV_KEY = 'verikloak.token'
    DEFAULT_USER_ENV_KEY = 'verikloak.user'

    # @param app [#call] downstream Rack app
    # @param discovery_url [String] OIDC discovery endpoint URL
    # @param audience [String, #call] Expected `aud` claim. When a callable is provided it
    #   receives the Rack env and may return a String or Array of audiences.
    # @param skip_paths [Array<String>] literal paths or wildcard patterns to bypass auth
    # @param discovery [Discovery, nil] custom discovery instance (for DI/tests)
    # @param jwks_cache [JwksCache, nil] custom JWKs cache instance (for DI/tests)
    # @param connection [Faraday::Connection, nil] Optional injected Faraday connection
    #   (defaults to {Verikloak::HTTP.default_connection})
    # @param leeway [Integer] Clock skew tolerance in seconds for token verification (delegated to TokenDecoder)
    # @param token_verify_options [Hash] Additional JWT verification options passed through
    #   to TokenDecoder.
    #   e.g., { verify_iat: false, leeway: 10 }
    def initialize(app,
                   discovery_url:,
                   audience:,
                   skip_paths: [],
                   discovery: nil,
                   jwks_cache: nil,
                   connection: nil,
                   leeway: Verikloak::TokenDecoder::DEFAULT_LEEWAY,
                   token_verify_options: {},
                   token_env_key: DEFAULT_TOKEN_ENV_KEY,
                   user_env_key: DEFAULT_USER_ENV_KEY,
                   realm: DEFAULT_REALM,
                   logger: nil)
      @app             = app
      @connection      = connection || Verikloak::HTTP.default_connection
      @audience_source = audience
      @discovery       = discovery || Discovery.new(discovery_url: discovery_url, connection: @connection)
      @jwks_cache      = jwks_cache
      @leeway = leeway
      @token_verify_options = token_verify_options || {}
      @issuer        = nil
      @mutex         = Mutex.new
      @decoder_cache = {}
      @token_env_key = normalize_env_key(token_env_key, 'token_env_key')
      @user_env_key  = normalize_env_key(user_env_key, 'user_env_key')
      @realm         = normalize_realm(realm)
      @logger        = logger

      compile_skip_paths(skip_paths)
    end

    # Rack entrypoint.
    #
    # @param env [Hash] Rack environment
    # @return [Array(Integer, Hash, Array<String>)] standard Rack response triple
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

    # Returns the Faraday connection used for HTTP operations (Discovery/JWKs).
    # Exposed for tests; not part of public API.
    def http_connection
      @connection
    end

    # Verifies the token, stores result in Rack env, and forwards to the downstream app.
    #
    # @param env [Hash]
    # @param token [String]
    # @return [Array(Integer, Hash, Array<String>)] Rack response triple
    def handle_request(env, token)
      claims = decode_token(env, token)
      env[@token_env_key] = token
      env[@user_env_key]  = claims
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
          %(Bearer realm="#{@realm}", error="#{code}", error_description="#{message.gsub('"', '\\"')}")
      end
      [status, headers, [body]]
    end

    # Logs unexpected internal errors to STDERR (non-PII). Used for diagnostics only.
    #
    # @param error [Exception]
    # @return [void]
    def log_internal_error(error)
      message = "[verikloak] Internal error: #{error.class} - #{error.message}"
      backtrace = error.backtrace&.join("\n")

      if @logger
        if @logger.respond_to?(:error)
          @logger.error(message)
        elsif @logger.respond_to?(:warn)
          @logger.warn(message)
        end

        if backtrace
          if @logger.respond_to?(:debug)
            @logger.debug(backtrace)
          elsif @logger.respond_to?(:error)
            @logger.error(backtrace)
          elsif @logger.respond_to?(:warn)
            @logger.warn(backtrace)
          end
        end
      else
        warn message
        warn backtrace if backtrace
      end
    end

    def normalize_env_key(value, option_name)
      normalized = value.to_s.strip
      raise ArgumentError, "#{option_name} cannot be blank" if normalized.empty?

      normalized
    end

    def normalize_realm(value)
      return DEFAULT_REALM if value.nil?

      normalized = value.to_s.strip
      raise ArgumentError, 'realm cannot be blank' if normalized.empty?

      normalized
    end
  end
end
