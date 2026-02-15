# frozen_string_literal: true

require 'json'

module Verikloak
  # Shared helpers for building RFC 6750 compliant JSON error responses.
  #
  # Provides a consistent format for error responses across all Verikloak middleware:
  # - JSON body with `{ error:, message: }` structure
  # - `WWW-Authenticate` header with Bearer scheme for 401 responses
  # - Header value sanitization to prevent injection attacks
  module ErrorResponse
    module_function

    # Build a JSON error response with optional RFC 6750 `WWW-Authenticate` header.
    #
    # @param code [String] The error code (e.g. "unauthorized", "insufficient_audience")
    # @param message [String] Human-readable error message
    # @param status [Integer] HTTP status code
    # @param realm [String] The realm value for WWW-Authenticate (default: "verikloak")
    # @return [Array(Integer, Hash, Array<String>)] Rack response triple
    def build(code:, message:, status:, realm: 'verikloak')
      body = { error: code, message: message }.to_json
      headers = { 'Content-Type' => 'application/json' }

      if status == 401
        realm_val = sanitize_header_value(realm)
        code_val  = sanitize_header_value(code)
        msg_val   = sanitize_header_value(message)
        headers['WWW-Authenticate'] =
          %(Bearer realm="#{realm_val}", error="#{code_val}", error_description="#{msg_val}")
      end

      [status, headers, [body]]
    end

    # Sanitizes a value for safe inclusion in HTTP header quoted-string fields.
    # Escapes backslashes and double-quotes, and strips CR/LF and other control characters.
    #
    # @param val [String, nil]
    # @return [String]
    def sanitize_header_value(val)
      s = val.to_s
      # Truncate at first CRLF sequence to prevent header injection
      s = s.split("\r\n", 2).first.to_s
      # Replace remaining lone CR or LF with spaces
      s = s.gsub(/[\r\n]/, ' ')
      s.gsub(/(["\\])/) { |m| "\\#{m}" }
       .gsub(/[[:cntrl:]]/, '')
    end
  end
end
