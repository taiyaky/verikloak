# frozen_string_literal: true

require 'faraday'
require 'ipaddr'
require 'json'
require 'resolv'
require 'uri'

require 'verikloak/http'
require 'verikloak/safe_url'

module Verikloak
  # Caches and revalidates JSON Web Key Sets (JWKs) fetched from a remote endpoint.
  #
  # This cache supports two HTTP cache mechanisms:
  # - **ETag revalidation** via `If-None-Match` → returns `304 Not Modified` when unchanged.
  # - **TTL freshness** via `Cache-Control: max-age` → avoids HTTP requests while fresh.
  #
  # On a successful `200 OK`, the cache:
  # - Parses the JWKs JSON (`{"keys":[...]}`) and validates each JWK has `kid`, `kty`, `n`, `e`.
  # - Stores the keys in-memory, records `ETag`, and computes freshness from `Cache-Control`.
  #
  # On a `304 Not Modified`, the cache:
  # - Keeps existing keys and ETag, optionally updates TTL from new `Cache-Control`, and refreshes `fetched_at`.
  #
  # Errors are raised as {Verikloak::JwksCacheError} with structured `code` values:
  # - `jwks_fetch_failed` (network/HTTP errors)
  # - `jwks_parse_failed` (invalid JSON / structure)
  # - `jwks_cache_miss`   (304 received but nothing cached)
  #
  # @example Basic usage
  #   cache = Verikloak::JwksCache.new(jwks_uri: "https://issuer.example.com/protocol/openid-connect/certs")
  #   keys  = cache.fetch! # → Array&lt;Hash&gt; of JWKs
  #
  # @see #fetch!
  # @see #cached
  #
  # ## Dependency Injection
  # Pass a preconfigured `Faraday::Connection` via `connection:` to control timeouts,
  # adapters, and shared headers (kept consistent with Discovery).
  #   `JwksCache.new(jwks_uri: "...", connection: Faraday.new { |f| f.request :retry })`
  class JwksCache
    # @param jwks_uri [String] HTTPS URL of the JWKs endpoint
    # @param connection [Faraday::Connection, nil] Optional Faraday connection for HTTP requests
    # @param allow_http [Boolean] When false (default), raises on plain HTTP URIs. Set true for local development only.
    # @raise [JwksCacheError] if the URI is not an HTTP(S) URL or resolves to a private/internal address
    def initialize(jwks_uri:, connection: nil, allow_http: false)
      clean_jwks_uri = SafeUrl.normalize(jwks_uri)

      unless clean_jwks_uri
        raise JwksCacheError.new('Invalid JWKs URI: must be a non-empty HTTP(S) URL', code: 'jwks_fetch_failed')
      end

      if SafeUrl.insecure_http?(clean_jwks_uri, allow_http: allow_http)
        raise JwksCacheError.new(
          'JWKs URI must use HTTPS. Set allow_http: true to permit plain HTTP (development only).',
          code: 'insecure_jwks_uri'
        )
      end

      validate_not_private!(clean_jwks_uri) unless allow_http

      @jwks_uri    = clean_jwks_uri
      @connection  = connection || Verikloak::HTTP.default_connection
      @cached_keys = nil
      @etag        = nil
      @fetched_at  = nil
      @max_age     = nil
      @mutex       = Mutex.new
    end

    # Fetches the JWKs and updates the in-memory cache.
    #
    # Performs an HTTP GET with `If-None-Match` when an ETag is present and handles:
    # - 200: parses/validates body, updates keys, ETag, TTL and `fetched_at`.
    # - 304: keeps cached keys, updates TTL from headers (if present), refreshes `fetched_at`.
    #
    # @param force [Boolean] When true, revalidates over HTTP even while
    #   `Cache-Control: max-age` freshness holds (the ETag conditional request
    #   still applies, so an unchanged key set costs only a 304).
    # @return [Array&lt;Hash&gt;] the cached JWKs after fetch/revalidation
    # @raise [JwksCacheError] on HTTP failures, invalid JSON, invalid structure, or cache miss on 304
    def fetch!(force: false)
      @mutex.synchronize do
        return @cached_keys if !force && fresh_by_ttl_locked?

        with_error_handling do
          # Build conditional request headers (ETag-based)
          headers  = build_conditional_headers
          # Perform HTTP GET request
          response = @connection.get(@jwks_uri, nil, headers)
          # Handle HTTP response according to status code
          handle_response(response)
        end
      end
    end

    # Revalidates the JWKs over HTTP regardless of TTL freshness.
    #
    # Used by the middleware's key-rotation retry path: a `Cache-Control:
    # max-age` on the previous response must not delay picking up rotated
    # keys when a token already failed with an unknown `kid` or bad signature.
    #
    # @return [Array&lt;Hash&gt;] the cached JWKs after revalidation
    # @raise [JwksCacheError] (see #fetch!)
    def force_fetch!
      fetch!(force: true)
    end

    # Returns the last cached JWKs without performing a network request.
    # @return [Array&lt;Hash&gt;, nil] cached keys, or nil if never fetched
    def cached
      @mutex.synchronize { @cached_keys }
    end

    # Timestamp of the last successful fetch or revalidation.
    # @return [Time, nil]
    def fetched_at
      @mutex.synchronize { @fetched_at }
    end

    # Injected Faraday connection (for testing and shared config across the gem)
    # @return [Faraday::Connection]
    attr_reader :connection

    # Whether the cache is considered stale.
    #
    # Uses `Cache-Control: max-age` semantics when available:
    # returns `true` if `max-age` has elapsed or nothing is cached.
    #
    # @return [Boolean]
    def stale?
      @mutex.synchronize { !fresh_by_ttl_locked? }
    end

    # @api private
    # Wraps network/parse errors into {JwksCacheError} with structured codes.
    # @raise [JwksCacheError]
    def with_error_handling
      yield
    rescue JwksCacheError
      raise
    rescue Faraday::ConnectionFailed, Faraday::TimeoutError
      raise JwksCacheError.new('Connection failed', code: 'jwks_fetch_failed')
    rescue Faraday::Error => e
      raise JwksCacheError.new("JWKs fetch failed: #{e.message}", code: 'jwks_fetch_failed')
    rescue JSON::ParserError
      raise JwksCacheError.new('Response is not valid JSON', code: 'jwks_parse_failed')
    rescue StandardError => e
      raise JwksCacheError.new("Unexpected JWKs fetch error: #{e.message}", code: 'jwks_fetch_failed')
    end

    # @api private
    # Builds conditional headers for revalidation.
    # @return [Hash] `{ 'If-None-Match' =&gt; etag }` when present, otherwise `{}`.
    def build_conditional_headers
      @etag ? { 'If-None-Match' => @etag } : {}
    end

    # @api private
    # True when cached keys are still fresh per `Cache-Control: max-age`.
    # @return [Boolean]
    def fresh_by_ttl?
      @mutex.synchronize { fresh_by_ttl_locked? }
    end

    private

    def fresh_by_ttl_locked?
      return false unless @cached_keys && @fetched_at && @max_age

      (Time.now - @fetched_at) < @max_age
    end

    # Validates that the JWKs URI does not resolve to a private/internal IP address (SSRF protection).
    #
    # Skipped when `allow_http: true` is set (development mode), since local Keycloak instances
    # typically run on private/loopback addresses.
    #
    # The discovery redirect flow already validates redirect targets, but the `jwks_uri` value
    # extracted from the discovery JSON document itself was not previously validated, allowing a
    # compromised or malicious discovery endpoint to point JWKs fetching at internal services.
    #
    # IPv4-mapped IPv6 addresses (e.g. `::ffff:127.0.0.1`) are normalised to their native IPv4
    # form before comparison (see {SafeUrl}).
    #
    # @api private
    # @param url [String] The JWKs URI to validate
    # @raise [JwksCacheError] when the URI resolves to a private/internal address
    def validate_not_private!(url)
      host = URI.parse(url).host
      return unless SafeUrl.resolves_to_private_ip?(host)

      raise JwksCacheError.new(
        "JWKs URI resolves to a private/internal address (#{host})",
        code: 'jwks_ssrf_blocked'
      )
    rescue URI::InvalidURIError => e
      raise JwksCacheError.new("Invalid JWKs URI: #{e.message}", code: 'jwks_fetch_failed')
    end

    # @api private
    # Parses a `Cache-Control` header and extracts `max-age` in seconds.
    #
    # Ignores `no-store` / `no-cache`. Returns `nil` when `max-age` is not present or invalid.
    #
    # @param cache_control [String, nil]
    # @return [Integer, nil] seconds
    def extract_max_age(cache_control)
      return nil unless cache_control

      # Normalize and split directives
      directives = cache_control.to_s.downcase.split(',').map(&:strip)
      return nil if directives.include?('no-store') || directives.include?('no-cache')

      max_age_directive = directives.find { |d| d.start_with?('max-age=') }
      return nil unless max_age_directive

      value = max_age_directive.split('=', 2)[1]
      Integer(value)
    rescue ArgumentError
      nil
    end

    # @api private
    # Parses the response body into JSON.
    # @param body [#to_s]
    # @return [Hash]
    # @raise [JwksCacheError] when JSON is invalid
    def parse_json!(body)
      JSON.parse(body.to_s)
    rescue JSON::ParserError
      raise JwksCacheError.new('Response is not valid JSON', code: 'jwks_parse_failed')
    end

    # @api private
    # Extracts and validates the `keys` array from a JWKs JSON document.
    # Ensures each key has `kid`, `kty`, `n`, and `e`.
    #
    # @param json [Hash]
    # @return [Array&lt;Hash&gt;]
    # @raise [JwksCacheError] when structure or attributes are invalid
    def extract_and_validate_keys!(json)
      keys = json['keys']
      unless keys.is_a?(Array)
        raise JwksCacheError.new("Response does not contain 'keys' array",
                                 code: 'jwks_parse_failed')
      end

      keys.each_with_index do |key, idx|
        %w[kid kty n e].each do |attr|
          raise JwksCacheError.new("JWK at index #{idx} missing '#{attr}'", code: 'jwks_parse_failed') unless key[attr]
        end
      end

      keys
    end

    # @api private
    # Updates cached keys and freshness metadata from a 200 OK response.
    #
    # @param response [Faraday::Response]
    # @param keys [Array&lt;Hash&gt;]
    # @return [void]
    def update_cache_from_ok(response, keys)
      @cached_keys = keys

      new_etag = response.headers['etag']
      @etag = new_etag if new_etag

      cache_control = response.headers['cache-control']
      @max_age      = extract_max_age(cache_control)
      @fetched_at   = Time.now
    end

    # @api private
    # Dispatches handling based on HTTP status.
    # @param response [Faraday::Response]
    # @return [Array&lt;Hash&gt;]
    # @raise [JwksCacheError]
    def handle_response(response)
      case response.status
      when 200
        process_successful_response(response)
      when 304
        # Revalidation succeeded; update freshness from 304 headers if present
        process_not_modified(response)
      else
        raise JwksCacheError.new("Failed to fetch JWKs: status #{response.status}", code: 'jwks_fetch_failed')
      end
    end

    # @api private
    # Handles a 200 OK JWKs response.
    # @param response [Faraday::Response]
    # @return [Array&lt;Hash&gt;] parsed and cached keys
    def process_successful_response(response)
      body = response.body.to_s
      if body.bytesize > Verikloak::HTTP::MAX_RESPONSE_BYTES
        raise JwksCacheError.new('JWKs response exceeds maximum allowed size', code: 'jwks_parse_failed')
      end

      json = parse_json!(body)
      keys = extract_and_validate_keys!(json)
      update_cache_from_ok(response, keys)
      keys
    end

    # @api private
    # Handles a 304 Not Modified JWKs response: updates TTL and timestamp, returns cached keys.
    # @param response [Faraday::Response]
    # @return [Array&lt;Hash&gt;]
    # @raise [JwksCacheError] when cache is empty
    def process_not_modified(response)
      # Update TTL from response headers (some servers include Cache-Control on 304)
      cache_control = response.headers['cache-control']
      @max_age      = extract_max_age(cache_control) || @max_age
      @fetched_at   = Time.now if @cached_keys
      return_from_cache_or_fail
    end

    # @api private
    # Returns cached keys or raises when 304 is received without prior cache.
    # @return [Array&lt;Hash&gt;]
    # @raise [JwksCacheError]
    def return_from_cache_or_fail
      @cached_keys || raise(JwksCacheError.new('JWKs cache is empty but received 304 Not Modified',
                                               code: 'jwks_cache_miss'))
    end
  end
end
