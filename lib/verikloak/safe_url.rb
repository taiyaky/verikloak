# frozen_string_literal: true

require 'ipaddr'
require 'resolv'

module Verikloak
  # Private IP ranges that must not be targets of outbound requests (SSRF protection).
  # Includes RFC 1918, loopback, link-local, and IPv6 equivalents.
  # @api private
  PRIVATE_IP_RANGES = [
    IPAddr.new('10.0.0.0/8'),
    IPAddr.new('172.16.0.0/12'),
    IPAddr.new('192.168.0.0/16'),
    IPAddr.new('127.0.0.0/8'),
    IPAddr.new('169.254.0.0/16'),
    IPAddr.new('0.0.0.0/8'),
    IPAddr.new('::1/128'),
    IPAddr.new('fc00::/7'),
    IPAddr.new('fe80::/10')
  ].freeze

  # @api private
  #
  # Shared URL normalization and SSRF-protection helpers used by
  # {Verikloak::Discovery} and {Verikloak::JwksCache}. Callers keep their own
  # error classes and codes; this module only answers questions about URLs.
  #
  # NOTE: The private-IP check resolves the hostname at validation time, while
  # the HTTP client resolves it again at connection time. A DNS rebinding
  # attack (short-TTL records) can therefore pass validation and still connect
  # to a private address. See SECURITY.md ("Known limitations").
  module SafeUrl
    module_function

    # Strips surrounding whitespace and verifies the value is an HTTP(S) URL.
    #
    # @param url [Object] Candidate URL (any type).
    # @return [String, nil] The stripped URL string, or nil when the value is
    #   not a String or does not start with http:// or https://.
    def normalize(url)
      return nil unless url.is_a?(String)

      normalized = url.strip
      normalized.match?(%r{\Ahttps?://}) ? normalized : nil
    end

    # Whether the URL uses plain HTTP while HTTP is not allowed.
    #
    # @param url [String] Normalized URL string.
    # @param allow_http [Boolean]
    # @return [Boolean]
    def insecure_http?(url, allow_http:)
      !allow_http && !url.start_with?('https://')
    end

    # Whether the hostname resolves to at least one private/internal address.
    #
    # IPv4-mapped IPv6 addresses (e.g. `::ffff:127.0.0.1`) are normalised to
    # their native IPv4 form before comparison. Addresses that cannot be
    # parsed are ignored (the HTTP client will surface any real connection
    # error).
    #
    # @param host [String, nil] Hostname or IP literal.
    # @return [Boolean]
    def resolves_to_private_ip?(host)
      return false if host.nil? || host.to_s.empty?

      Resolv.getaddresses(host).any? { |addr| private_address?(addr) }
    end

    # Whether a single address string falls within {PRIVATE_IP_RANGES}.
    #
    # @param address [String]
    # @return [Boolean]
    def private_address?(address)
      ip = IPAddr.new(address)
      ip = ip.native if ip.ipv4_mapped?
      PRIVATE_IP_RANGES.any? { |range| range.include?(ip) }
    rescue IPAddr::InvalidAddressError
      false
    end
  end
end
