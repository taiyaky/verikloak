# frozen_string_literal: true

require 'rack'
require 'digest'
require 'json'
require 'set'
require 'faraday'

require 'verikloak/http'
require 'verikloak/skip_path_matcher'
require 'verikloak/error_response'

module Verikloak
  # @api private
  #
  # Internal mixin for audience resolution with dynamic callable support.
  # Handles various callable signatures and parameter detection.
  module MiddlewareAudienceResolution
    private

    # Resolves the expected audience for the current request.
    #
    # @param env [Hash] Rack environment.
    # @return [String, Array<String>] The expected audience value.
    # @raise [MiddlewareError] when the resolved audience is blank.
    def resolve_audience(env)
      source = @audience_source
      value = if source.respond_to?(:call)
                callable = source
                call_with_optional_env(callable, env)
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
    def call_with_optional_env(callable, env)
      params = callable_parameters(callable)

      invocation_chain(params).each do |strategy|
        return strategy.call(callable, env)
      rescue ArgumentError => e
        raise unless wrong_arity_error?(e)
      end

      callable.call
    end

    # Returns true when the ArgumentError message indicates a wrong arity.
    # Anchored to the start of the message so ArgumentErrors raised inside the
    # callable body that merely mention the phrase are not swallowed.
    #
    # @param error [ArgumentError]
    # @return [Boolean]
    def wrong_arity_error?(error)
      error.message.start_with?('wrong number of arguments')
    end

    # Extracts parameter information from a callable's call method.
    #
    # @param callable [#call] The callable object to inspect.
    # @return [Array<Array>, nil] Parameter information as returned by Method#parameters,
    #   or nil if the method cannot be resolved.
    def callable_parameters(callable)
      callable.method(:call).parameters
    rescue NameError
      nil
    end

    # Builds a chain of invocation strategies based on callable parameters.
    #
    # @param params [Array<Array>, nil] Parameter information from Method#parameters.
    # @return [Array<Proc>] Ordered array of lambda strategies to try when calling the callable.
    def invocation_chain(params)
      strategies = []

      if params.nil?
        # When parameters are unknown, try strategies in safe order:
        # 1. Try with positional argument first (most common)
        # 2. Try with no arguments as fallback
        strategies << ->(callable, env) { callable.call(env) }
        strategies << ->(callable, _env) { callable.call }
      else
        # When parameters are known, try most specific to least specific
        strategies << ->(callable, env) { callable.call(env: env) } if accepts_keyword_env?(params)
        strategies << ->(callable, env) { callable.call(env) } if accepts_positional_env?(params)
        strategies << ->(callable, _env) { callable.call } if accepts_zero_arguments?(params)
      end

      strategies
    end

    # Determines if a callable accepts keyword arguments, specifically env: parameter.
    #
    # @param params [Array<Array>, nil] Parameter information from Method#parameters.
    # @return [Boolean] true if the callable accepts keyword arguments including env.
    def accepts_keyword_env?(params)
      return false if params.nil?

      params.any? do |type, name|
        type == :keyrest ||
          (%i[keyreq key].include?(type) && (name.nil? || name == :env))
      end
    end

    # Determines if a callable accepts positional arguments.
    #
    # @param params [Array<Array>, nil] Parameter information from Method#parameters.
    # @return [Boolean] true if the callable accepts positional arguments.
    def accepts_positional_env?(params)
      return false if params.nil?

      params.any? { |type, _| %i[req opt rest].include?(type) }
    end

    # Determines if a callable accepts zero arguments (no required parameters).
    #
    # @param params [Array<Array>, nil] Parameter information from Method#parameters.
    # @return [Boolean] true if the callable can be called with no arguments.
    def accepts_zero_arguments?(params)
      return false if params.nil?

      # Only accepts zero arguments if parameters are empty
      # or all parameters are optional/keyword/blocks
      params.empty? || params.all? { |type, _| %i[opt key keyrest block].include?(type) }
    end
  end

  # @api private
  #
  # Internal mixin for configuration validation and logging utilities.
  # Extracted to keep the main Middleware class focused and under line limits.
  module MiddlewareConfiguration
    private

    # Validates and normalizes the decoder cache limit configuration.
    #
    # @param limit [Integer, nil] The cache limit value to normalize.
    # @return [Integer, nil] The normalized limit, or nil if no limit.
    # @raise [ArgumentError] if the limit is negative or invalid.
    def normalize_decoder_cache_limit(limit)
      return nil if limit.nil?

      value = Integer(limit)
      raise ArgumentError, 'decoder_cache_limit must be zero or positive' if value.negative?

      value
    rescue ArgumentError, TypeError
      raise ArgumentError, 'decoder_cache_limit must be zero or positive'
    end

    # Validates and normalizes the JWKs refresh interval configuration.
    #
    # @param interval [Numeric, nil] Minimum seconds between JWKs revalidations.
    # @return [Numeric] The normalized interval (nil becomes 0 = revalidate every request).
    # @raise [ArgumentError] if the interval is negative or not numeric.
    def normalize_jwks_refresh_interval(interval)
      return 0 if interval.nil?

      raise ArgumentError, 'jwks_refresh_interval must be zero or positive' unless interval.is_a?(Numeric)
      raise ArgumentError, 'jwks_refresh_interval must be zero or positive' if interval.negative?

      interval
    end

    # Validates and normalizes environment key configuration.
    #
    # @param value [String, #to_s] The environment key to normalize.
    # @param option_name [String] The name of the option for error messages.
    # @return [String] The normalized environment key.
    # @raise [ArgumentError] if the key is blank after normalization.
    def normalize_env_key(value, option_name)
      normalized = value.to_s.strip
      raise ArgumentError, "#{option_name} cannot be blank" if normalized.empty?

      normalized
    end

    # Validates and normalizes the realm configuration.
    #
    # @param value [String, #to_s, nil] The realm value to normalize.
    # @return [String] The normalized realm, or DEFAULT_REALM if nil.
    # @raise [ArgumentError] if the realm is blank after normalization.
    def normalize_realm(value)
      return DEFAULT_REALM if value.nil?

      normalized = value.to_s.strip
      raise ArgumentError, 'realm cannot be blank' if normalized.empty?

      normalized
    end

    # Checks if a logger instance is available and responds to logging methods.
    #
    # @return [Boolean] true if a logger is available and can log messages.
    def logger_available?
      return false unless @logger

      @logger.respond_to?(:error) || @logger.respond_to?(:warn) || @logger.respond_to?(:debug)
    end

    # @return [Float] Monotonic clock reading in seconds.
    def monotonic_now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    # Logs a message and backtrace using the configured logger.
    #
    # @param message [String] The primary error message to log.
    # @param backtrace [String, nil] The backtrace information to log.
    # @return [void]
    def log_with_logger(message, backtrace)
      log_message(@logger, message)
      log_backtrace(@logger, backtrace)
    end

    # Logs a message using the most appropriate logger method.
    #
    # @param logger [Logger] The logger instance to use.
    # @param message [String] The message to log.
    # @return [void]
    def log_message(logger, message)
      if logger.respond_to?(:error)
        logger.error(message)
      elsif logger.respond_to?(:warn)
        logger.warn(message)
      end
    end

    # Logs backtrace information using the most appropriate logger method.
    #
    # @param logger [Logger] The logger instance to use.
    # @param backtrace [String, nil] The backtrace information to log.
    # @return [void]
    def log_backtrace(logger, backtrace)
      return unless backtrace

      if logger.respond_to?(:debug)
        logger.debug(backtrace)
      elsif logger.respond_to?(:error)
        logger.error(backtrace)
      elsif logger.respond_to?(:warn)
        logger.warn(backtrace)
      end
    end
  end

  # @api private
  #
  # Internal mixin for decoder cache management with LRU eviction.
  # Handles TokenDecoder instance caching and cleanup.
  module MiddlewareDecoderCache
    private

    # Stores a decoder in the cache and updates access order if tracking is enabled.
    #
    # @param cache_key [String] The cache key for the decoder
    # @param decoder [TokenDecoder] The decoder instance to cache
    # @return [TokenDecoder] The cached decoder instance
    def store_decoder_cache(cache_key, decoder)
      @decoder_cache[cache_key] = decoder
      touch_decoder_cache(cache_key) if track_decoder_order?
      decoder
    end

    # Prunes the decoder cache to stay within the configured limit.
    # Removes the oldest entries when the cache size exceeds the limit.
    #
    # @return [void]
    def prune_decoder_cache_if_needed
      return unless track_decoder_order?

      while @decoder_cache_order.length >= @decoder_cache_limit
        oldest = @decoder_cache_order.shift
        @decoder_cache.delete(oldest)
      end
    end

    # Updates the access order for a cache entry to mark it as recently used.
    # Moves the cache key to the end of the order queue for LRU tracking.
    #
    # @param cache_key [String] The cache key to mark as recently accessed
    # @return [void]
    def touch_decoder_cache(cache_key)
      @decoder_cache_order.delete(cache_key)
      @decoder_cache_order << cache_key
    end

    # Checks if decoder cache order tracking is enabled.
    # Returns true if cache limit is set and positive.
    #
    # @return [Boolean] true if order tracking is enabled
    def track_decoder_order?
      @decoder_cache_limit&.positive?
    end

    # Clears all cached decoder instances and order tracking.
    # Removes all entries from both the cache and order queue.
    #
    # @return [void]
    def clear_decoder_cache
      @decoder_cache.clear
      @decoder_cache_order.clear
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
      error.is_a?(TokenDecoderError) && %w[invalid_signature kid_not_found].include?(error.code)
    end

    # Returns a cached TokenDecoder instance for current inputs.
    # Cache key uses issuer, audience, leeway, token_verify_options, and the
    # current JWKs content identity (so content-identical refreshes reuse decoders).
    #
    # @param audience [String, #call] The audience to create a decoder for
    # @return [TokenDecoder] A decoder instance for the given audience
    def decoder_for(audience)
      keys = @jwks_cache.cached
      cache_key = [
        @issuer,
        audience,
        @leeway,
        @token_verify_options,
        decoder_cache_generation
      ]
      @mutex.synchronize do
        if (decoder = @decoder_cache[cache_key])
          touch_decoder_cache(cache_key) if track_decoder_order?
          return decoder
        end

        decoder = TokenDecoder.new(
          jwks: keys,
          issuer: @issuer,
          audience: audience,
          leeway: @leeway,
          options: @token_verify_options
        )

        return decoder if @decoder_cache_limit&.zero?

        prune_decoder_cache_if_needed
        store_decoder_cache(cache_key, decoder)
      end
    end

    # Decodes and verifies the JWT using the cached JWKs. On certain verification
    # failures (e.g., key rotation), it refreshes the JWKs and retries once.
    #
    # @param env [Hash] The Rack environment hash
    # @param token [String] The JWT token to decode and verify
    # @return [Hash] Decoded JWT claims
    # @raise [Verikloak::Error] bubbles up verification/fetch errors for centralized handling
    def decode_token(env, token)
      ensure_jwks_cache!
      keys = @jwks_cache.cached
      if keys.nil? || keys.empty?
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

        ensure_jwks_cache!(force: true)

        # Rebuild decoder with refreshed keys and try once more.
        decoder = decoder_for(audience)
        decoder.decode!(token)
      end
    end

    # Ensures that discovery metadata and JWKs cache are initialized and up-to-date.
    # This method is thread-safe.
    #
    # * When the cache instance is missing, it is created from discovery metadata.
    # * JWKs revalidation is throttled by `jwks_refresh_interval` so that hot
    #   request paths do not serialize on a network call; ETag/Cache-Control
    #   headers minimize traffic when a revalidation does happen.
    # * `force: true` bypasses the throttle **and** the cache's own
    #   `Cache-Control: max-age` freshness (used by the key-rotation retry
    #   path, where waiting out a TTL would keep rejecting freshly-signed
    #   tokens).
    #
    # @param force [Boolean] Revalidate even when the throttle window is still open.
    # @return [void]
    # @raise [Verikloak::DiscoveryError, Verikloak::JwksCacheError, Verikloak::MiddlewareError]
    def ensure_jwks_cache!(force: false)
      return if !force && jwks_recently_refreshed?

      @mutex.synchronize do
        initialize_jwks_dependencies!

        if force || !jwks_recently_refreshed?
          refresh_jwks!(force: force)
          @last_jwks_refresh_at = monotonic_now
        end

        purge_decoder_cache_if_keys_changed
      end
    rescue Verikloak::DiscoveryError, Verikloak::JwksCacheError => e
      # Re-raise so that specific error codes can be mapped in the middleware
      raise e
    rescue StandardError => e
      raise MiddlewareError.new("Failed to initialize JWKs cache: #{e.message}", code: 'jwks_fetch_failed')
    end

    # Creates the JWKs cache from discovery metadata and resolves the effective
    # issuer. Must be called while holding `@mutex`.
    #
    # @return [void]
    def initialize_jwks_dependencies!
      if @jwks_cache.nil?
        config   = @discovery.fetch!
        # Use configured issuer if provided, otherwise use discovered issuer
        @issuer  = @configured_issuer || config['issuer']
        jwks_uri = config['jwks_uri']
        @jwks_cache = JwksCache.new(jwks_uri: jwks_uri, connection: @connection, allow_http: @allow_http)
      elsif @configured_issuer.nil? && @issuer.nil?
        # If jwks_cache was injected but no issuer configured and not yet discovered, fetch discovery to set issuer
        config = @discovery.fetch!
        @issuer = config['issuer']
      end
    end

    # Revalidates the JWKs cache. On the forced path, prefers
    # {JwksCache#force_fetch!} so that a `Cache-Control: max-age` from the
    # previous response cannot short-circuit the revalidation and leave the
    # retry decoding against pre-rotation keys. Injected caches that only
    # implement a plain `fetch!` keep their existing behavior.
    #
    # @param force [Boolean]
    # @return [void]
    def refresh_jwks!(force: false)
      if force && @jwks_cache.respond_to?(:force_fetch!)
        @jwks_cache.force_fetch!
      else
        @jwks_cache.fetch!
      end
    end

    # Whether the JWKs were revalidated within the configured refresh interval.
    # Reads shared state without the mutex; a stale read only causes an extra
    # (harmless) pass through the synchronized slow path.
    #
    # @return [Boolean]
    def jwks_recently_refreshed?
      return false unless @jwks_refresh_interval.positive?
      return false if @issuer.nil? || @jwks_cache.nil? || @last_cached_keys_id.nil?

      last = @last_jwks_refresh_at
      !last.nil? && (monotonic_now - last) < @jwks_refresh_interval
    end

    # Purges the decoder cache if the JWKs have changed since last check.
    # Compares key set content identity to detect key rotation and invalidate
    # cached decoders.
    #
    # @return [void]
    def purge_decoder_cache_if_keys_changed
      current_id = cached_keys_identity(@jwks_cache)
      clear_decoder_cache if @last_cached_keys_id && current_id && @last_cached_keys_id != current_id

      @last_cached_keys_id = current_id if current_id
    end

    # Cache-key component tying decoders to the JWKs content they were built from.
    # Falls back to the fetch timestamp when the content digest is unavailable.
    #
    # @return [String, Time, nil]
    def decoder_cache_generation
      @last_cached_keys_id || (@jwks_cache.respond_to?(:fetched_at) ? @jwks_cache.fetched_at : nil)
    end

    # Generates a content-based identity for the current JWKs set, stable across
    # refreshes that return identical keys (unlike object identity).
    #
    # @param cache [JwksCache] The JWKs cache instance
    # @return [String, nil] A digest representing the current key set, or nil
    #   when unavailable
    def cached_keys_identity(cache)
      return unless cache.respond_to?(:cached)

      keys = cache.cached
      return unless keys

      canonical = Array(keys).map do |key|
        key.respond_to?(:to_h) ? key.to_h.transform_keys(&:to_s).sort.inspect : key.inspect
      end
      Digest::SHA256.hexdigest(canonical.inspect)
    rescue StandardError
      nil
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

    # Determines if an error code should result in a 403 Forbidden response.
    #
    # @param code [String, nil] The error code to check
    # @return [Boolean] true if the error should be treated as a 403 Forbidden
    def forbidden?(code)
      code == 'forbidden'
    end

    # Determines if an error code belongs to authentication-related errors.
    #
    # @param code [String, nil] The error code to check
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
    include MiddlewareConfiguration
    include MiddlewareAudienceResolution
    include MiddlewareDecoderCache
    include MiddlewareTokenVerification

    DEFAULT_REALM = 'verikloak'
    DEFAULT_TOKEN_ENV_KEY = 'verikloak.token'
    DEFAULT_USER_ENV_KEY = 'verikloak.user'

    # @param app [#call] downstream Rack app
    # @param discovery_url [String] OIDC discovery endpoint URL
    # @param audience [String, #call] Expected `aud` claim. When a callable is provided it
    #   receives the Rack env and may return a String or Array of audiences.
    # @param issuer [String, nil] Optional issuer override (defaults to discovery `issuer`)
    # @param skip_paths [Array<String>] literal paths or wildcard patterns to bypass auth
    # @param discovery [Discovery, nil] custom discovery instance (for DI/tests)
    # @param jwks_cache [JwksCache, nil] custom JWKs cache instance (for DI/tests)
    # @param connection [Faraday::Connection, nil] Optional injected Faraday connection
    #   (defaults to {Verikloak::HTTP.default_connection})
    # @param leeway [Integer] Clock skew tolerance in seconds for token verification (delegated to TokenDecoder)
    # @param token_verify_options [Hash] Additional JWT verification options passed through
    #   to TokenDecoder.
    #   e.g., { verify_iat: false, leeway: 10 }
    # @param jwks_refresh_interval [Numeric] Minimum seconds between JWKs
    #   revalidations on the request path. Set to `0` to revalidate on every
    #   request (pre-1.1 behavior). Key rotation within the window is still
    #   handled: a signature/kid mismatch forces an immediate refresh and retry.
    # rubocop:disable Metrics/ParameterLists
    DEFAULT_DECODER_CACHE_LIMIT = 128
    DEFAULT_JWKS_REFRESH_INTERVAL = 60

    def initialize(app,
                   discovery_url:,
                   audience:,
                   issuer: nil,
                   skip_paths: [],
                   discovery: nil,
                   jwks_cache: nil,
                   connection: nil,
                   leeway: Verikloak::TokenDecoder::DEFAULT_LEEWAY,
                   token_verify_options: {},
                   decoder_cache_limit: DEFAULT_DECODER_CACHE_LIMIT,
                   jwks_refresh_interval: DEFAULT_JWKS_REFRESH_INTERVAL,
                   token_env_key: DEFAULT_TOKEN_ENV_KEY,
                   user_env_key: DEFAULT_USER_ENV_KEY,
                   realm: DEFAULT_REALM,
                   logger: nil,
                   allow_http: false)
      @app             = app
      @connection      = connection || Verikloak::HTTP.default_connection
      @audience_source = audience
      @discovery       = discovery || Discovery.new(discovery_url: discovery_url, connection: @connection,
                                                    allow_http: allow_http)
      @jwks_cache      = jwks_cache
      @allow_http      = allow_http
      @leeway = leeway
      @token_verify_options = token_verify_options || {}
      @decoder_cache_limit = normalize_decoder_cache_limit(decoder_cache_limit)
      @jwks_refresh_interval = normalize_jwks_refresh_interval(jwks_refresh_interval)
      @last_jwks_refresh_at = nil
      # Optional user-configured issuer (overrides discovery issuer when provided)
      @configured_issuer = issuer
      # Effective issuer; may be nil initially and set via discovery if not configured
      @issuer        = @configured_issuer
      @mutex         = Mutex.new
      @decoder_cache = {}
      @decoder_cache_order = []
      @last_cached_keys_id = nil
      @token_env_key = normalize_env_key(token_env_key, 'token_env_key')
      @user_env_key  = normalize_env_key(user_env_key, 'user_env_key')
      @realm         = normalize_realm(realm)
      @logger        = logger

      compile_skip_paths(skip_paths)
    end
    # rubocop:enable Metrics/ParameterLists

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

    # Maximum token size in bytes to prevent DoS via oversized JWTs.
    # Aligned with BFF's {Verikloak::BFF::Constants::MAX_TOKEN_BYTES}.
    MAX_TOKEN_BYTES = 8192

    private

    # Returns the Faraday connection used for HTTP operations (Discovery/JWKs).
    # Exposed for tests; not part of public API.
    #
    # @return [Faraday::Connection] The HTTP connection instance
    def http_connection
      @connection
    end

    # Verifies the token, stores result in Rack env, and forwards to the downstream app.
    #
    # @param env [Hash] The Rack environment hash
    # @param token [String] The extracted JWT token
    # @return [Array(Integer, Hash, Array<String>)] Rack response triple
    def handle_request(env, token)
      claims = decode_token(env, token)
      env[@token_env_key] = token
      env[@user_env_key]  = claims
      @app.call(env)
    end

    # Extracts the Bearer token from the `Authorization` header.
    #
    # @param env [Hash] The Rack environment hash
    # @return [String] The raw JWT string
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

      if token.bytesize > MAX_TOKEN_BYTES
        raise MiddlewareError.new('Token exceeds maximum allowed size', code: 'invalid_token')
      end

      token
    end

    # Converts a raised error into a `[code, http_status]` tuple for response rendering.
    #
    # @param error [Exception] The exception to map
    # @return [Array(String, Integer)] A tuple of error code and HTTP status
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
    # Delegates to {Verikloak::ErrorResponse} for consistent formatting across gems.
    #
    # @param code [String] The error code to include in the response
    # @param message [String] The error message to include in the response
    # @param status [Integer] The HTTP status code for the response
    # @return [Array(Integer, Hash, Array<String>)] Rack response triple
    def error_response(code = 'unauthorized', message = 'Unauthorized', status = 401)
      Verikloak::ErrorResponse.build(code: code, message: message, status: status, realm: @realm)
    end

    # Logs unexpected internal errors to STDERR (non-PII). Used for diagnostics only.
    #
    # @param error [Exception]
    # @return [void]
    def log_internal_error(error)
      message = "[verikloak] Internal error: #{error.class} - #{error.message}"
      backtrace = error.backtrace&.join("\n")

      if logger_available?
        log_with_logger(message, backtrace)
      else
        warn message
        warn backtrace if backtrace
      end
    end
  end
end
