# This test file verifies the behavior and error handling of the Verikloak::JwksCache class.

# frozen_string_literal: true

require "spec_helper"

RSpec.describe Verikloak::JwksCache do
  let(:jwks_uri) { "https://example.com/realms/myrealm/protocol/openid-connect/certs" }
  let(:valid_jwks) do
    {
      keys: [
        {
          kty: "RSA",
          use: "sig",
          kid: "test-key",
          n: "abc",
          e: "AQAB"
        }
      ]
    }.to_json
  end

  # Test fetching and caching valid JWKs on first request
  it "fetches and caches valid JWKs on first request" do
    # Stub HTTP GET to return valid JWKs with ETag header
    stub_request(:get, jwks_uri)
      .to_return(status: 200, body: valid_jwks, headers: { "Content-Type" => "application/json", "ETag" => "W/\"abc123\"" })

    cache = described_class.new(jwks_uri: jwks_uri)
    keys = cache.fetch!

    expect(keys).to be_an(Array)
    expect(keys.first["kid"]).to eq("test-key")
    expect(cache.cached).to eq(keys)
    expect(cache.fetched_at).to be_within(2).of(Time.now)
  end

  # Test returning cached keys when server responds with 304 Not Modified
  it "returns cached keys on 304 Not Modified" do
    # Stub initial fetch with valid JWKs and ETag
    stub_request(:get, jwks_uri)
      .to_return(status: 200, body: valid_jwks, headers: { "ETag" => "W/\"abc123\"" })

    cache = described_class.new(jwks_uri: jwks_uri)
    cache.fetch! # initial fetch to cache it

    # Stub subsequent fetch with If-None-Match header and 304 response
    stub_request(:get, jwks_uri)
      .with(headers: { "If-None-Match" => "W/\"abc123\"" })
      .to_return(status: 304)

    keys = cache.fetch!
    expect(keys).to eq(cache.cached)
  end

  # Test error raised when JWKs response is not valid JSON
  it "raises error when JWKs response is not valid JSON" do
    # Stub HTTP GET to return invalid JSON body
    stub_request(:get, jwks_uri)
      .to_return(status: 200, body: "not-json")

    cache = described_class.new(jwks_uri: jwks_uri)
    expect {
      cache.fetch!
    }.to raise_error(Verikloak::JwksCacheError, /not valid JSON/)
  end

  # Test error raised when JWKs response does not contain 'keys' array
  it "raises error when JWKs response is missing keys array" do
    # Stub HTTP GET to return JSON without keys array
    stub_request(:get, jwks_uri)
      .to_return(status: 200, body: { foo: "bar" }.to_json)

    cache = described_class.new(jwks_uri: jwks_uri)
    expect {
      cache.fetch!
    }.to raise_error(Verikloak::JwksCacheError, /does not contain 'keys' array/)
  end

  # Test error raised on failed HTTP request (connection failure)
  it "raises error on failed HTTP request" do
    # Stub HTTP GET to raise connection failure error
    stub_request(:get, jwks_uri)
      .to_raise(Faraday::ConnectionFailed.new("connection failed"))

    cache = described_class.new(jwks_uri: jwks_uri)
    expect {
      cache.fetch!
    }.to raise_error(Verikloak::JwksCacheError, /Connection failed/)
  end

  # Invalid URL at initialization
  it "raises on invalid jwks_uri format" do
    expect {
      described_class.new(jwks_uri: "ftp://bad")
    }.to raise_error(Verikloak::JwksCacheError) { |e|
      expect(e.message).to match(/Invalid JWKs URI/)
      expect(e.code).to eq("jwks_fetch_failed")
    }
  end

  # Non-200/304 unexpected status
  it "raises on unexpected HTTP status" do
    stub_request(:get, jwks_uri).to_return(status: 418, body: "")
    cache = described_class.new(jwks_uri: jwks_uri)
    expect {
      cache.fetch!
    }.to raise_error(Verikloak::JwksCacheError) { |e|
      expect(e.message).to match(/Failed to fetch JWKs: status 418/)
      expect(e.code).to eq("jwks_fetch_failed")
    }
  end

  # 304 Not Modified without prior cache
  it "raises jwks_cache_miss on 304 without prior cache" do
    stub_request(:get, jwks_uri).to_return(status: 304)
    cache = described_class.new(jwks_uri: jwks_uri)
    expect {
      cache.fetch!
    }.to raise_error(Verikloak::JwksCacheError) { |e|
      expect(e.message).to match(/JWKs cache is empty/)
      expect(e.code).to eq("jwks_cache_miss")
    }
  end

  # Missing required attributes on a JWK
  it "raises when a JWK is missing required attributes" do
    bad_jwks = { keys: [ { kty: "RSA", kid: "a", n: "x" } ] }.to_json # missing 'e'
    stub_request(:get, jwks_uri).to_return(status: 200, body: bad_jwks)
    cache = described_class.new(jwks_uri: jwks_uri)
    expect {
      cache.fetch!
    }.to raise_error(Verikloak::JwksCacheError) { |e|
      expect(e.message).to match(/missing 'e'/)
      expect(e.code).to eq("jwks_parse_failed")
    }
  end

  # Save ETag then send If-None-Match on subsequent request
  it "stores ETag and sends If-None-Match on subsequent request" do
    stub_request(:get, jwks_uri)
      .to_return(status: 200, body: valid_jwks, headers: { "ETag" => 'W/"abc123"' })

    cache = described_class.new(jwks_uri: jwks_uri)
    cache.fetch!

    stub = stub_request(:get, jwks_uri)
             .with(headers: { "If-None-Match" => 'W/"abc123"' })
             .to_return(status: 304)

    cache.fetch!
    expect(stub).to have_been_requested
  end

  # Faraday::TimeoutError mapping
  it "maps Faraday::TimeoutError to jwks_fetch_failed" do
    stub_request(:get, jwks_uri).to_raise(Faraday::TimeoutError.new("timeout"))
    cache = described_class.new(jwks_uri: jwks_uri)
    expect {
      cache.fetch!
    }.to raise_error(Verikloak::JwksCacheError) { |e|
      expect(e.message).to match(/Connection failed/)
      expect(e.code).to eq("jwks_fetch_failed")
    }
  end

  # Generic Faraday::Error mapping
  it "maps generic Faraday::Error to jwks_fetch_failed with message" do
    stub_request(:get, jwks_uri).to_raise(Faraday::ClientError.new("boom"))
    cache = described_class.new(jwks_uri: jwks_uri)
    expect {
      cache.fetch!
    }.to raise_error(Verikloak::JwksCacheError) { |e|
      expect(e.message).to match(/JWKs fetch failed: boom/)
      expect(e.code).to eq("jwks_fetch_failed")
    }
  end

  # Initial cached state
  it "returns nil for cached before any fetch" do
    cache = described_class.new(jwks_uri: jwks_uri)
    expect(cache.cached).to be_nil
    expect(cache.fetched_at).to be_nil
  end

  # Cache-Control: max-age should control TTL-based freshness
  it "respects Cache-Control max-age for TTL freshness" do
    # Initial 200 with Cache-Control: max-age=120
    stub_request(:get, jwks_uri)
      .to_return(
        status: 200,
        body: valid_jwks,
        headers: { "ETag" => 'W/"ttl123"', "Cache-Control" => "public, max-age=120" }
      )

    cache = described_class.new(jwks_uri: jwks_uri)

    # Freeze time by stubbing Time.now sequentially
    t0 = Time.now
    allow(Time).to receive(:now).and_return(t0)

    # First fetch, cache keys and set TTL (max-age)
    cache.fetch!
    expect(cache.cached).to be_an(Array)
    expect(cache.stale?).to eq(false)  # fresh at t0

    # Still fresh before TTL expiry
    allow(Time).to receive(:now).and_return(t0 + 119)
    expect(cache.stale?).to eq(false)

    # Becomes stale after TTL
    allow(Time).to receive(:now).and_return(t0 + 121)
    expect(cache.stale?).to eq(true)
  end

  it "returns cached keys without hitting network while TTL is fresh" do
    stub_request(:get, jwks_uri)
      .to_return(
        status: 200,
        body: valid_jwks,
        headers: { "ETag" => 'W/"ttl-keep"', "Cache-Control" => "max-age=60" }
      )

    cache = described_class.new(jwks_uri: jwks_uri)
    t0 = Time.now
    allow(Time).to receive(:now).and_return(t0)

    cache.fetch!

    allow(Time).to receive(:now).and_return(t0 + 30)

    expect(cache.fetch!).to eq(cache.cached)
    expect(WebMock).to have_requested(:get, jwks_uri).once
  end

  # 304 Not Modified may update Cache-Control and should extend TTL from revalidation time
  it "updates TTL on 304 Not Modified with Cache-Control header" do
    # Initial 200 with ETag and max-age=60
    stub_request(:get, jwks_uri)
      .to_return(
        status: 200,
        body: valid_jwks,
        headers: { "ETag" => 'W/"reval1"', "Cache-Control" => "max-age=60" }
      )

    cache = described_class.new(jwks_uri: jwks_uri)
    t0 = Time.now
    allow(Time).to receive(:now).and_return(t0)

    cache.fetch!
    expect(cache.stale?).to eq(false)

    # Next request: server returns 304 with a larger max-age=120
    stub_request(:get, jwks_uri)
      .with(headers: { "If-None-Match" => 'W/"reval1"' })
      .to_return(
        status: 304,
        headers: { "Cache-Control" => "max-age=120" }
      )

    # Revalidation at t0 + 10s
    allow(Time).to receive(:now).and_return(t0 + 10)
    cache.fetch!

    # After revalidation, TTL is 120 from the new fetched_at (t0 + 10)
    allow(Time).to receive(:now).and_return(t0 + 10 + 119)
    expect(cache.stale?).to eq(false)

    allow(Time).to receive(:now).and_return(t0 + 10 + 121)
    expect(cache.stale?).to eq(true)
  end

  # --- Injected Faraday connection behaviors ---
  it "uses the injected Faraday connection (test adapter) for HTTP requests" do
    stubs = Faraday::Adapter::Test::Stubs.new
    conn  = Faraday.new do |f|
      f.adapter :test, stubs
    end

    stubs.get(jwks_uri) do |env|
      expect(env.url.to_s).to eq(jwks_uri)
      [
        200,
        { "Content-Type" => "application/json", "ETag" => 'W/"abc123"' },
        valid_jwks
      ]
    end

    cache = described_class.new(jwks_uri: jwks_uri, connection: conn)
    keys = cache.fetch!

    expect(keys).to be_an(Array)
    expect(keys.first["kid"]).to eq("test-key")
    stubs.verify_stubbed_calls
  end

  it "revalidation uses If-None-Match via injected connection" do
    stubs = Faraday::Adapter::Test::Stubs.new
    conn  = Faraday.new { |f| f.adapter :test, stubs }

    # 1st: 200 with ETag
    stubs.get(jwks_uri) do
      [
        200,
        { "Content-Type" => "application/json", "ETag" => 'W/"abc123"' },
        valid_jwks
      ]
    end

    cache = described_class.new(jwks_uri: jwks_uri, connection: conn)
    cache.fetch!

    # 2nd: expect If-None-Match header to be sent; respond 304
    stubs.get(jwks_uri) do |env|
      expect(env.request_headers["If-None-Match"]).to eq('W/"abc123"')
      [304, {}, ""]
    end

    expect(cache.fetch!).to eq(cache.cached)
    stubs.verify_stubbed_calls
  end

  it "maps Faraday::TimeoutError from injected connection to jwks_fetch_failed" do
    stubs = Faraday::Adapter::Test::Stubs.new
    conn  = Faraday.new { |f| f.adapter :test, stubs }

    stubs.get(jwks_uri) { raise Faraday::TimeoutError, "timeout" }

    cache = described_class.new(jwks_uri: jwks_uri, connection: conn)
    expect { cache.fetch! }.to raise_error(Verikloak::JwksCacheError) { |e|
      expect(e.code).to eq("jwks_fetch_failed")
      expect(e.message).to match(/Connection failed|timeout/i)
    }

    stubs.verify_stubbed_calls
  end

  it "sends custom headers configured on injected Faraday connection" do
    stubs = Faraday::Adapter::Test::Stubs.new
    conn  = Faraday.new do |f|
      f.headers["User-Agent"] = "verikloak/spec"
      f.adapter :test, stubs
    end

    stubs.get(jwks_uri) do |env|
      expect(env.request_headers["User-Agent"]).to eq("verikloak/spec")
      [200, { "ETag" => 'W/"ua1"', "Content-Type" => "application/json" }, valid_jwks]
    end

    cache = described_class.new(jwks_uri: jwks_uri, connection: conn)
    cache.fetch!
    stubs.verify_stubbed_calls
  end
end
