# This test suite verifies the behavior of the Verikloak::Discovery class, ensuring it correctly handles various HTTP responses from the OpenID Connect discovery endpoint.

# frozen_string_literal: true

require "spec_helper"

RSpec.describe Verikloak::Discovery do
  let(:discovery_url) { "https://example.com/.well-known/openid-configuration" }

  # Scenario: The HTTP response is successful and contains valid discovery data
  context "when response is successful and valid" do
    # Stub a successful HTTP response with valid JSON containing jwks_uri and issuer
    before do
      stub_request(:get, discovery_url).to_return(
        status: 200,
        body: {
          jwks_uri: "https://example.com/keys",
          issuer: "https://example.com/"
        }.to_json,
        headers: { "Content-Type" => "application/json" }
      )
    end

    # Verify that the parsed configuration includes the expected jwks_uri
    it "returns the parsed configuration" do
      config = described_class.new(discovery_url: discovery_url).fetch!
      expect(config["jwks_uri"]).to eq("https://example.com/keys")
    end
  end

  # Scenario: The HTTP response is successful but missing the required jwks_uri field
  context "when response is missing jwks_uri" do
    # Stub a successful HTTP response with JSON missing the jwks_uri field
    before do
      stub_request(:get, discovery_url).to_return(
        status: 200,
        body: { issuer: "https://example.com/" }.to_json,
        headers: { "Content-Type" => "application/json" }
      )
    end

    # Verify that a DiscoveryError is raised indicating the missing jwks_uri
    it "raises a DiscoveryError" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError, /missing 'jwks_uri'/)
    end
  end

  # Scenario: The HTTP response is successful but contains invalid JSON
  context "when response is not valid JSON" do
    # Stub a successful HTTP response with a non-JSON body
    before do
      stub_request(:get, discovery_url).to_return(
        status: 200,
        body: "not-json"
      )
    end

    # Verify that a DiscoveryError is raised due to non-JSON content
    it "raises a DiscoveryError" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError, /Discovery response is not valid JSON/)
    end
  end

  # Scenario: The HTTP request to the discovery endpoint fails due to connection issues
  context "when HTTP request fails" do
    # Stub a connection failure when making the HTTP request
    before do
      stub_request(:get, discovery_url).to_raise(Faraday::ConnectionFailed.new("connection error"))
    end

    # Verify that a DiscoveryError is raised indicating connection failure
    it "raises a DiscoveryError" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError, /Could not connect to discovery endpoint/)
    end
  end

  # Scenario: Redirect (3xx) with valid Location is followed and parsed
  context "when response is a redirect with Location" do
    before do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://example.com/redirected-config" }
      )
      stub_request(:get, "https://example.com/redirected-config").to_return(
        status: 200,
        body: {
          jwks_uri: "https://example.com/keys",
          issuer: "https://example.com/"
        }.to_json,
        headers: { "Content-Type" => "application/json" }
      )
    end

    it "follows the redirect and returns the parsed configuration" do
      config = described_class.new(discovery_url: discovery_url).fetch!
      expect(config["issuer"]).to eq("https://example.com/")
    end
  end

  # Scenario: Redirect without Location header
  context "when response is a redirect without Location" do
    before do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { }
      )
    end

    it "raises a DiscoveryError with discovery_redirect_error code" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.message).to match(/Redirect without Location header/)
        expect(e.code).to eq("discovery_redirect_error")
      }
    end
  end

  # Scenario: 404 Not Found
  context "when response is 404" do
    before do
      stub_request(:get, discovery_url).to_return(status: 404, body: "")
    end

    it "raises discovery_metadata_fetch_failed" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.message).to match(/not found/i)
        expect(e.code).to eq("discovery_metadata_fetch_failed")
      }
    end
  end

  # Scenario: 5xx Server Error
  context "when response is 5xx" do
    before do
      stub_request(:get, discovery_url).to_return(status: 502, body: "")
    end

    it "raises discovery_metadata_fetch_failed" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.message).to match(/server error: status 502/i)
        expect(e.code).to eq("discovery_metadata_fetch_failed")
      }
    end
  end

  # Scenario: Unexpected HTTP status
  context "when response is an unexpected HTTP status" do
    before do
      stub_request(:get, discovery_url).to_return(status: 418, body: "")
    end

    it "raises discovery_metadata_fetch_failed" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.message).to match(/Failed to fetch discovery document: status 418/)
        expect(e.code).to eq("discovery_metadata_fetch_failed")
      }
    end
  end

  # Scenario: Timeout maps to discovery_metadata_fetch_failed
  context "when Faraday timeout occurs" do
    before do
      stub_request(:get, discovery_url).to_raise(Faraday::TimeoutError.new("timeout"))
    end

    it "raises discovery_metadata_fetch_failed" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.message).to match(/request timed out/i)
        expect(e.code).to eq("discovery_metadata_fetch_failed")
      }
    end
  end

  # Scenario: Generic Faraday error
  context "when a generic Faraday error occurs" do
    before do
      stub_request(:get, discovery_url).to_raise(Faraday::ClientError.new("boom"))
    end

    it "raises discovery_metadata_fetch_failed with message" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.message).to match(/Discovery request failed: boom/)
        expect(e.code).to eq("discovery_metadata_fetch_failed")
      }
    end
  end

  # Scenario: Missing required issuer field
  context "when response is missing issuer" do
    before do
      stub_request(:get, discovery_url).to_return(
        status: 200,
        body: { jwks_uri: "https://example.com/keys" }.to_json,
        headers: { "Content-Type" => "application/json" }
      )
    end

    it "raises discovery_metadata_invalid" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.message).to match(/missing 'issuer'/)
        expect(e.code).to eq("discovery_metadata_invalid")
      }
    end
  end

  # Scenario: Cache returns without making a second HTTP call
  context "when called twice within TTL" do
    it "uses the in-memory cache on the second call" do
      stub = stub_request(:get, discovery_url).to_return(
        status: 200,
        body: {
          jwks_uri: "https://example.com/keys",
          issuer: "https://example.com/"
        }.to_json
      )

      discovery = described_class.new(discovery_url: discovery_url, cache_ttl: 3600)
      first = discovery.fetch!
      expect(first["issuer"]).to eq("https://example.com/")

      # Do not stub a second response; ensure no extra HTTP request happens
      second = discovery.fetch!
      expect(second).to eq(first)
      expect(stub).to have_been_requested.once
    end
  end

  # Scenario: Invalid URL at initialization
  context "when initialized with an invalid discovery_url" do
    it "raises invalid_discovery_url" do
      expect {
        described_class.new(discovery_url: "ftp://bad")
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.message).to match(/Invalid discovery URL/)
        expect(e.code).to eq("invalid_discovery_url")
      }
    end
  end

  # Scenario: Multiple redirects within the allowed hops (<= 3)
  context "when there are multiple redirects within the limit" do
    before do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://example.com/config-1" }
      )
      stub_request(:get, "https://example.com/config-1").to_return(
        status: 302,
        headers: { "Location" => "https://example.com/config-2" }
      )
      stub_request(:get, "https://example.com/config-2").to_return(
        status: 200,
        body: {
          jwks_uri: "https://example.com/keys",
          issuer: "https://example.com/"
        }.to_json,
        headers: { "Content-Type" => "application/json" }
      )
    end

    it "follows up to two redirects and returns the parsed configuration" do
      config = described_class.new(discovery_url: discovery_url).fetch!
      expect(config["jwks_uri"]).to eq("https://example.com/keys")
    end
  end

  # Scenario: Too many redirects exceeding the maximum hops (3)
  context "when redirects exceed the maximum hops" do
    before do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://example.com/hop1" }
      )
      stub_request(:get, "https://example.com/hop1").to_return(
        status: 302,
        headers: { "Location" => "https://example.com/hop2" }
      )
      stub_request(:get, "https://example.com/hop2").to_return(
        status: 302,
        headers: { "Location" => "https://example.com/hop3" }
      )
      stub_request(:get, "https://example.com/hop3").to_return(
        status: 302,
        headers: { "Location" => "https://example.com/hop4" }
      )
    end

    it "raises discovery_redirect_error for too many redirects" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.message).to match(/Too many redirects/i)
        expect(e.code).to eq("discovery_redirect_error")
      }
    end
  end

  # Scenario: Relative Location header is resolved against the original URL
  context "when redirect Location is a relative path" do
    before do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "/redirected-config" }
      )
      stub_request(:get, "https://example.com/redirected-config").to_return(
        status: 200,
        body: {
          jwks_uri: "https://example.com/keys",
          issuer: "https://example.com/"
        }.to_json,
        headers: { "Content-Type" => "application/json" }
      )
    end

    it "resolves the relative Location and returns the parsed configuration" do
      config = described_class.new(discovery_url: discovery_url).fetch!
      expect(config["issuer"]).to eq("https://example.com/")
    end
  end

  # Scenario: Location header casing variations are handled (case-insensitive)
  context "when Location header casing is non-standard" do
    before do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "location" => "https://example.com/redirected-config" } # lower-case
      )
      stub_request(:get, "https://example.com/redirected-config").to_return(
        status: 200,
        body: {
          jwks_uri: "https://example.com/keys",
          issuer: "https://example.com/"
        }.to_json
      )
    end

    it "still follows the redirect and parses the configuration" do
      config = described_class.new(discovery_url: discovery_url).fetch!
      expect(config["jwks_uri"]).to eq("https://example.com/keys")
    end
  end

  # Scenario: After following redirect, the target responds with invalid JSON
  context "when redirected target returns invalid JSON" do
    before do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://example.com/redirected-config" }
      )
      stub_request(:get, "https://example.com/redirected-config").to_return(
        status: 200,
        body: "not-json"
      )
    end

    it "raises discovery_metadata_invalid from the redirected response" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.message).to match(/not valid JSON/i)
        expect(e.code).to eq("discovery_metadata_invalid")
      }
    end
  end

  # Scenario: After following redirect, the target responds with 404/5xx and is mapped correctly
  context "when redirected target responds with 404" do
    before do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://example.com/redirected-config" }
      )
      stub_request(:get, "https://example.com/redirected-config").to_return(
        status: 404,
        body: ""
      )
    end

    it "raises discovery_metadata_fetch_failed for 404 after redirect" do
      expect {
        described_class.new(discovery_url: discovery_url).fetch!
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.message).to match(/Failed to fetch discovery document: status 404/)
        expect(e.code).to eq("discovery_metadata_fetch_failed")
      }
    end
  end
end
