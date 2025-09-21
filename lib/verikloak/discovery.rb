# frozen_string_literal: true

require 'faraday'
require 'json'
require 'uri'

require 'verikloak/http'

module Verikloak
  # Fetches and caches the OpenID Connect Discovery document.
  #
  # This class retrieves the discovery metadata from an OpenID Connect provider
  # (e.g., Keycloak) using the `.well-known/openid-configuration` endpoint.
  # It validates required fields such as `jwks_uri` and `issuer`, and supports:
  #
  # - Dependency Injection of Faraday connection for testing and middleware
  # - In-memory caching with configurable TTL
  # - Thread safety via Mutex
  # - Automatic handling of common HTTP statuses (including multi-hop redirects)
  #
  # ### Thread-safety
  # `#fetch!` is synchronized, so concurrent callers share the same cached value and refresh.
  #
  # ### Errors
  # Raises {Verikloak::DiscoveryError} with one of the following `code`s:
  # - `invalid_discovery_url`
  # - `discovery_metadata_fetch_failed`
  # - `discovery_metadata_invalid`
  # - `discovery_redirect_error`
  #
  # @example Basic usage
  #   discovery = Verikloak::Discovery.new(
  #     discovery_url: "https://keycloak.example.com/realms/demo/.well-known/openid-configuration"
  #   )
  #   json = discovery.fetch!
  #   json["issuer"]   #=> "https://keycloak.example.com/realms/demo"
  #   json["jwks_uri"] #=> "https://keycloak.example.com/realms/demo/protocol/openid-connect/certs"
  class Discovery
    # Required keys that must be present in the discovery document.
    # @return [Array&lt;String&gt;]
    REQUIRED_FIELDS = %w[jwks_uri issuer].freeze

    # @param discovery_url [String] The full URL to the `.well-known/openid-configuration`.
    # @param connection [Faraday::Connection] Optional Faraday client (for DI/tests).
    # @param cache_ttl [Integer] Cache TTL in seconds (default: 3600).
    # @raise [DiscoveryError] when `discovery_url` is not a valid HTTP(S) URL
    def initialize(discovery_url:, connection: Verikloak::HTTP.default_connection, cache_ttl: 3600)
      unless discovery_url.is_a?(String) && discovery_url.strip.match?(%r{^https?://})
        raise DiscoveryError.new('Invalid discovery URL: must be a non-empty HTTP(S) URL',
                                 code: 'invalid_discovery_url')
      end

      @discovery_url = discovery_url
      @conn          = connection
      @cache_ttl     = cache_ttl
      @cached_json   = nil
      @fetched_at    = nil
      @mutex         = Mutex.new
    end

    # Fetches and parses the discovery document, using the in-memory cache if fresh.
    #
    # Cache freshness is determined by `cache_ttl` from initialization.
    #
    # @return [Hash] Parsed JSON object containing discovery metadata.
    # @raise [DiscoveryError] if the request fails, the response is invalid, or required fields are missing.
    def fetch!
      @mutex.synchronize do
        # Return cached if within TTL
        return @cached_json if @cached_json && (Time.now - @fetched_at) < @cache_ttl

        # Fetch fresh document
        json = with_error_handling { fetch_and_parse_json_from_url }
        validate_required_fields!(json)

        # Update cache
        @cached_json = json
        @fetched_at  = Time.now
        json
      end
    end

    private

    # Performs the initial HTTP GET and handles redirects, returning the parsed JSON.
    # @api private
    # @return [Hash]
    def fetch_and_parse_json_from_url
      response = @conn.get(@discovery_url)
      response = follow_redirects(response, max_hops: 3, base_url: @discovery_url)
      handle_final_response(response)
    end

    # Handles terminal (non-redirect) responses and parses JSON on 200 OK.
    # Maps common failure statuses to {DiscoveryError} with appropriate codes.
    # @api private
    # @param response [Faraday::Response]
    # @return [Hash]
    # @raise [DiscoveryError]
    def handle_final_response(response)
      status = response.status
      return parse_json(response.body) if status == 200

      if status == 404
        # If the 404 occurred after a redirect (final URL differs from the original discovery URL),
        # keep the generic message to align with redirect tests; otherwise use a specific "not found" message.
        final_url = response.respond_to?(:env) && response.env&.url ? response.env.url.to_s : nil
        message = if final_url && final_url != @discovery_url
                    'Failed to fetch discovery document: status 404'
                  else
                    'Discovery document not found (404)'
                  end
        raise DiscoveryError.new(message, code: 'discovery_metadata_fetch_failed')
      end
      if (500..599).cover?(status)
        raise DiscoveryError.new("Discovery endpoint server error: status #{status}",
                                 code: 'discovery_metadata_fetch_failed')
      end

      raise DiscoveryError.new("Failed to fetch discovery document: status #{status}",
                               code: 'discovery_metadata_fetch_failed')
    end

    # Follows HTTP redirects up to `max_hops`, resolving relative `Location` values.
    # @api private
    # @param response [Faraday::Response]
    # @param max_hops [Integer]
    # @param base_url [String]
    # @return [Faraday::Response] the final (non-redirect) response
    # @raise [DiscoveryError] when exceeding hops or encountering invalid/missing Location
    def follow_redirects(response, max_hops:, base_url:)
      hops = 0
      current = response
      base = base_url

      while redirect_status?(current.status)
        if hops >= max_hops
          raise DiscoveryError.new("Too many redirects (max #{max_hops})",
                                   code: 'discovery_redirect_error')
        end

        location = location_from(current)
        url = absolutize_location(location, base)
        current = @conn.get(url)
        base = url
        hops += 1
      end

      current
    end

    # Returns true if status is an HTTP redirect.
    # @api private
    # @param status [Integer]
    # @return [Boolean]
    def redirect_status?(status)
      [301, 302, 303, 307, 308].include?(status)
    end

    # Extracts and normalizes the Location header, raising when missing.
    # @api private
    # @param response [Faraday::Response]
    # @return [String] absolute or relative URL string
    # @raise [DiscoveryError]
    def location_from(response)
      raw = response.headers || {}
      headers = {}
      raw.each { |k, v| headers[k.to_s.downcase] = v }
      location = headers['location'].to_s.strip
      raise DiscoveryError.new('Redirect without Location header', code: 'discovery_redirect_error') if location.empty?

      location
    end

    # Resolves a possibly-relative Location value to an absolute URL string.
    # @api private
    # @param location [String]
    # @param base_url [String]
    # @return [String] absolute URL
    # @raise [DiscoveryError] when location is an invalid URI
    def absolutize_location(location, base_url)
      uri = URI.parse(location)
      return location if uri.absolute?

      base = URI.parse(base_url)
      URI.join(base, location).to_s
    rescue URI::InvalidURIError => e
      raise DiscoveryError.new("Redirect Location is invalid: #{e.message}", code: 'discovery_redirect_error')
    end

    # Parses a JSON string and maps parse errors to {DiscoveryError}.
    # @api private
    # @param body [String]
    # @return [Hash]
    # @raise [DiscoveryError]
    def parse_json(body)
      JSON.parse(body)
    rescue JSON::ParserError
      raise DiscoveryError.new('Discovery response is not valid JSON', code: 'discovery_metadata_invalid')
    end

    # Validates HTTP response success status (helper, currently unused).
    # @api private
    # @param response [Faraday::Response]
    # @return [void]
    # @raise [DiscoveryError]
    def validate_http_status!(response)
      return if response.success?

      raise DiscoveryError.new("Failed to fetch discovery document: status #{response.status}",
                               code: 'discovery_metadata_fetch_failed')
    end

    # Wraps a block with network and parsing error handling and re-raising as {DiscoveryError}.
    # @api private
    # @yield
    # @return [Object] the block result
    # @raise [DiscoveryError]
    def with_error_handling
      yield
    rescue Verikloak::DiscoveryError
      # Re-raise library-specific discovery errors without altering their code/message
      raise
    rescue Faraday::ConnectionFailed
      raise DiscoveryError.new('Could not connect to discovery endpoint', code: 'discovery_metadata_fetch_failed')
    rescue Faraday::TimeoutError
      raise DiscoveryError.new('Discovery endpoint request timed out', code: 'discovery_metadata_fetch_failed')
    rescue Faraday::Error => e
      raise DiscoveryError.new("Discovery request failed: #{e.message}", code: 'discovery_metadata_fetch_failed')
    rescue StandardError => e
      raise DiscoveryError.new("Unexpected discovery error: #{e.message}", code: 'discovery_metadata_fetch_failed')
    end

    # Ensures all required fields exist in the discovery JSON document.
    # @api private
    # @param json [Hash]
    # @return [void]
    # @raise [DiscoveryError]
    def validate_required_fields!(json)
      REQUIRED_FIELDS.each do |field|
        unless json[field]
          raise DiscoveryError.new("Discovery document is missing '#{field}'",
                                   code: 'discovery_metadata_invalid')
        end
      end
    end
  end
end
