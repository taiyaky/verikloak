# frozen_string_literal: true

require 'faraday'
require 'faraday/retry'

module Verikloak
  # Internal HTTP helpers shared across components.
  module HTTP
    # Default request timeout (seconds) for outbound discovery/JWKs calls.
    DEFAULT_TIMEOUT = 5
    # Default open/read timeout (seconds) before establishing the HTTP connection.
    DEFAULT_OPEN_TIMEOUT = 2

    # Retry middleware configuration used for idempotent GET requests.
    # Retries on 429/5xx with exponential backoff and jitter.
    RETRY_OPTIONS = {
      max: 2,
      interval: 0.1,
      interval_randomness: 0.2,
      backoff_factor: 2,
      methods: %i[get],
      retry_statuses: [429, 500, 502, 503, 504]
    }.freeze

    # Builds a Faraday connection with conservative defaults suitable for
    # network-bound operations (discovery and JWKs fetching).
    #
    # @return [Faraday::Connection]
    def self.default_connection
      Faraday.new do |f|
        f.request :retry, RETRY_OPTIONS
        f.options.timeout = DEFAULT_TIMEOUT
        f.options.open_timeout = DEFAULT_OPEN_TIMEOUT
        f.adapter Faraday.default_adapter
      end
    end
  end
end
