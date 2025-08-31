# frozen_string_literal: true

require 'jwt'

module Verikloak
  # Verifies JWT tokens using a JWKs.
  #
  # This class validates a JWT's signature and standard claims (`iss`, `aud`, `exp`, `nbf`, etc.)
  # using the appropriate RSA public key selected by the JWT's `kid` header.
  # Only `RS256`-signed tokens with RSA JWKs are supported.
  # It also supports a configurable clock skew (`leeway`) to account for minor time drift.
  #
  # @example
  #   decoder = Verikloak::TokenDecoder.new(
  #     jwks: jwks_keys,
  #     issuer: "https://keycloak.example.com/realms/myrealm",
  #     audience: "my-client-id",
  #     leeway: 30  # allow 30 seconds clock skew
  #   )
  #   payload = decoder.decode!(token)
  #   puts payload["sub"]
  #
  class TokenDecoder
    # Default clock skew tolerance in seconds.
    DEFAULT_LEEWAY = 60

    # Initializes the decoder with a JWKs and verification criteria.
    #
    # @param jwks     [Array<Hash>] List of JWKs from the discovery document.
    # @param issuer   [String]      Expected `iss` value in the token.
    # @param audience [String]      Expected `aud` value in the token.
    # @param leeway   [Integer]     Clock skew tolerance in seconds (optional).
    # @param options [Hash] Extra JWT verification options.
    #   Mirrors ruby-jwt options (e.g., :leeway, :verify_iat, :verify_expiration, :verify_not_before, :algorithms).
    #   NOTE: If both `leeway:` and `options[:leeway]` are provided, `options[:leeway]` takes precedence.
    def initialize(jwks:, issuer:, audience:, leeway: DEFAULT_LEEWAY, options: {})
      @jwks     = jwks
      @issuer   = issuer
      @audience = audience
      # Keep backward compatibility; can be overridden by options[:leeway]
      @leeway   = leeway
      # Normalize and store verification options
      @options  = symbolize_keys(options || {})
      @options_without_leeway = @options.except(:leeway).freeze

      # Build a kid-indexed hash for O(1) JWK lookup
      @jwk_by_kid = {}
      Array(@jwks).each do |j|
        kid_key = fetch_indifferent(j, 'kid')
        @jwk_by_kid[kid_key] = j if kid_key
      end
      @options.freeze
    end

    # Decodes and verifies a JWT.
    #
    # @param token [String] The JWT string to verify.
    # @return [Hash] The decoded payload (claims).
    # @raise [TokenDecoderError] If verification fails. Possible error codes:
    #   - invalid_token
    #   - expired_token
    #   - not_yet_valid
    #   - invalid_issuer
    #   - invalid_audience
    #   - invalid_signature
    #   - unsupported_algorithm
    def decode!(token)
      with_error_handling do
        # Extract header without verifying signature (payload is ignored here).
        header = JWT.decode(token, nil, false).last
        validate_header(header)                       # check alg and kid present
        jwk        = find_key_by_kid(header)          # locate JWK by kid
        public_key = rsa_key_from_jwk(jwk)            # import RSA public key
        payload = decode_with_public_key(token, public_key) # verify signature & claims
        payload
      end
    end

    private

    # Validates the JWT header.
    #
    # Rules:
    # - Algorithm must be exactly 'RS256'
    # - 'kid' must be present
    #
    # @param header [Hash]
    # @raise [TokenDecoderError] If the algorithm is not RS256 or 'kid' is missing.
    def validate_header(header)
      alg = fetch_indifferent(header, 'alg')
      unless alg.is_a?(String) && alg == 'RS256'
        raise TokenDecoderError.new('Missing or unsupported algorithm',
                                    code: 'unsupported_algorithm')
      end

      kid = fetch_indifferent(header, 'kid')
      raise TokenDecoderError.new("JWT header missing 'kid'", code: 'invalid_token') unless kid
    end

    # Finds the JWK matching the kid in the JWT header.
    #
    # @param header [Hash]
    # @return [Hash] The matching JWK.
    # @raise [TokenDecoderError] If key not found or unsupported type.
    def find_key_by_kid(header)
      kid = fetch_indifferent(header, 'kid')
      jwk = @jwk_by_kid[kid]

      raise TokenDecoderError.new("Key with kid=#{kid} not found in JWKs", code: 'invalid_token') unless jwk

      jwk
    end

    # Decodes and verifies the token using the given public key and decode options.
    #
    # @param token      [String] JWT to verify.
    # @param public_key [OpenSSL::PKey::RSA] Public key for verification.
    # @return [Hash] Verified claims (payload).
    def decode_with_public_key(token, public_key)
      payload, = JWT.decode(token, public_key, true, jwt_decode_options)
      payload
    end

    # Returns the verification options passed to JWT.decode.
    #
    # Enforces:
    # - Allowed signature algorithms (RS256)
    # - Issuer and audience validation
    # - Expiration (`exp`) and not-before (`nbf`) checks
    # - Clock skew tolerance via `leeway`
    #
    # @return [Hash]
    def jwt_decode_options
      base = {
        algorithms: ['RS256'],
        iss: @issuer,
        verify_iss: true,
        aud: @audience,
        verify_aud: true,
        verify_iat: true,
        verify_expiration: true,
        verify_not_before: true
      }
      # options[:leeway] overrides top-level @leeway if provided
      leeway = @options.key?(:leeway) ? @options[:leeway] : @leeway
      merged = base.merge(leeway: leeway)
      # Merge remaining options last (excluding :leeway which is already applied)
      extra = @options_without_leeway
      merged.merge(extra)
    end

    # Imports an OpenSSL::PKey::RSA public key from the given JWK.
    #
    # @param jwk [Hash] JWK hash containing 'n', 'e', etc.
    # @return [OpenSSL::PKey::RSA]
    # @raise [TokenDecoderError] If import fails.
    def rsa_key_from_jwk(jwk)
      normalized = jwk.transform_keys(&:to_s)

      # Pre-validate minimal RSA JWK requirements for stable error behavior
      kty = normalized['kty']
      n   = normalized['n']
      e   = normalized['e']

      unless kty == 'RSA'
        raise TokenDecoderError.new("Unsupported key type '#{kty}'. Only RSA is supported", code: 'invalid_token')
      end

      # Accept only non-empty String for n/e to avoid nil/empty/incorrect types
      unless n.is_a?(String) && !n.empty? && e.is_a?(String) && !e.empty?
        raise TokenDecoderError.new('Failed to import JWK: missing required parameter(s)', code: 'invalid_token')
      end

      # Try importing — any failure is wrapped consistently
      JWT::JWK::RSA.import(normalized).public_key
    rescue StandardError => e
      raise TokenDecoderError.new("Failed to import JWK: #{e.message}", code: 'invalid_token')
    end

    # Fetches a value from a hash, allowing indifferent access by string or symbol keys.
    #
    # @param hash [Hash] The hash to look up the key in. (Non-hash values return nil.)
    # @param key [String, Symbol] The key to retrieve, as a string or symbol.
    # @return [Object, nil] The value associated with the key, or nil if not found or if the input is not a Hash.
    def fetch_indifferent(hash, key)
      return nil unless hash.is_a?(Hash)

      hash[key] || hash[key.to_s] || hash[key.to_sym]
    end

    # Wraps decoding logic with structured error handling.
    #
    # @yield Executes the core decoding steps.
    # @return [Hash] Decoded payload.
    # @raise [TokenDecoderError] On verification failure.
    def with_error_handling
      yield
    rescue TokenDecoderError => e
      # Pass through our own structured errors without rewrapping
      raise e
    rescue *jwt_errors => e
      code = case e
             when JWT::ExpiredSignature then 'expired_token'
             when JWT::ImmatureSignature then 'not_yet_valid'
             when JWT::InvalidIssuerError then 'invalid_issuer'
             when JWT::InvalidAudError then 'invalid_audience'
             when defined?(JWT::VerificationError) && e.is_a?(JWT::VerificationError) then 'invalid_signature'
             when defined?(JWT::IncorrectAlgorithm) && e.is_a?(JWT::IncorrectAlgorithm) then 'unsupported_algorithm'
             else 'invalid_token'
             end
      raise TokenDecoderError.new(jwt_error_message(e), code: code)
    rescue StandardError => e
      raise TokenDecoderError.new("Unexpected token verification error: #{e.message}", code: 'invalid_token')
    end

    # JWT-related exceptions to catch and rewrap.
    #
    # @return [Array<Class>]
    def jwt_errors
      [
        JWT::ExpiredSignature,
        JWT::ImmatureSignature,
        JWT::InvalidIssuerError,
        JWT::InvalidAudError,
        (JWT::InvalidIatError if defined?(JWT::InvalidIatError)),
        (JWT::VerificationError if defined?(JWT::VerificationError)),
        (JWT::IncorrectAlgorithm if defined?(JWT::IncorrectAlgorithm)),
        JWT::DecodeError
      ].compact
    end

    # Maps JWT exception classes to user-friendly messages.
    #
    # @param error [Exception]
    # @return [String]
    def jwt_error_message(error)
      {
        JWT::ExpiredSignature => 'Token has expired',
        JWT::ImmatureSignature => 'Token is not yet valid (nbf in the future)',
        JWT::InvalidIssuerError => 'Invalid issuer (iss claim)',
        JWT::InvalidAudError => 'Invalid audience (aud claim)',
        JWT::InvalidIatError => 'Invalid issued-at (iat) claim'
      }.fetch(error.class) { fallback_jwt_error_message(error) }
    end

    # Fallback for unexpected JWT errors.
    #
    # @param error [Exception]
    # @return [String]
    def fallback_jwt_error_message(error)
      if error.is_a?(JWT::DecodeError)
        "JWT decode failed: #{error.message}"
      else
        "JWT verification failed: #{error.message}"
      end
    end

    def symbolize_keys(hash)
      return {} unless hash.is_a?(Hash)

      hash.transform_keys(&:to_sym)
    end
  end
end
