# This test suite verifies the authentication and error handling behavior of the Verikloak::Middleware Rack middleware.

# frozen_string_literal: true

require "rack/test"
require "verikloak"

RSpec.describe Verikloak::Middleware do
  include Rack::Test::Methods

  let(:inner_app) do
    ->(env) { [200, { "Content-Type" => "text/plain" }, ["OK"]] }
  end
  
  let(:middleware) do
    described_class.new(inner_app,
      discovery_url: "https://example.com/.well-known/openid-configuration",
      audience: "my-client-id")
  end

  def app
    middleware
  end

  let(:decoder) { instance_double("Verikloak::TokenDecoder") }

  before do
    # Mock the Discovery
    allow_any_instance_of(Verikloak::Discovery).to receive(:fetch!)
      .and_return({ "issuer" => "https://example.com/", "jwks_uri" => "https://example.com/jwks" })

    # Mock the JWKS cache
    allow_any_instance_of(Verikloak::JwksCache).to receive(:fetch!).and_return(true)
    allow_any_instance_of(Verikloak::JwksCache).to receive(:cached).and_return([{"kid" => "dummy"}])

    # Replace all TokenDecoder.new calls with this decoder instance
    allow(Verikloak::TokenDecoder).to receive(:new).and_return(decoder)
  end

  context "when token is valid" do
    # Test scenario: Valid token is provided, middleware should authenticate and pass request downstream
    before do
      allow(decoder).to receive(:decode!).and_return({ "sub" => "user1" })
    end

    it "calls downstream app and sets env" do
      # Verifies that middleware sets user info in env and calls inner app when token is valid
      header "Authorization", "Bearer valid.token"
      get "/"
      expect(last_response.status).to eq 200
      expect(last_request.env["verikloak.user"]).to eq({ "sub" => "user1" })
    end
  end

  context "when Authorization header is missing" do
    # Test scenario: No Authorization header present, middleware should reject request
    it "returns 401 Unauthorized" do
      # Checks that missing Authorization header results in 401 response with appropriate error
      get "/"
      expect(last_response.status).to eq 401
      json = JSON.parse(last_response.body)
      expect(json["error"]).to eq("missing_authorization_header")
      expect(json["message"]).to match(/Missing Authorization header/i)
      expect(last_response.headers["WWW-Authenticate"]).to match(/error="missing_authorization_header"/)
    end
  end

  context "when token verification fails" do
    # Test scenario: Token is present but invalid, decoding fails and middleware should reject
    before do
      allow(decoder).to receive(:decode!)
        .and_raise(Verikloak::TokenDecoderError.new("JWT decode failed", code: "invalid_token"))
    end

    it "returns 401 Unauthorized" do
      # Confirms that invalid token causes 401 response with error message indicating failure
      header "Authorization", "Bearer invalid.token"
      get "/"
      expect(last_response.status).to eq 401
      json = JSON.parse(last_response.body)
      expect(json["error"]).to eq("invalid_token")
      expect(json["message"]).to match(/JWT decode failed/i)
      expect(last_response.headers["WWW-Authenticate"]).to match(/error="invalid_token"/)
    end
  end

  context "when Authorization header is malformed" do
    # Test scenario: Authorization header format is incorrect, middleware should reject
    it "returns 401 Unauthorized" do
      # Ensures malformed Authorization header leads to 401 unauthorized response
      header "Authorization", "Something invalid"
      get "/"
      expect(last_response.status).to eq 401
      json = JSON.parse(last_response.body)
      expect(json["error"]).to eq("invalid_authorization_header")
      expect(json["message"]).to match(/Invalid Authorization header format/i)
      expect(last_response.headers["WWW-Authenticate"]).to match(/error="invalid_authorization_header"/)
    end
  end

  context "when token is expired" do
    # Test scenario: Token is expired, decoding raises error and middleware rejects request
    before do
      allow(decoder).to receive(:decode!)
        .and_raise(Verikloak::TokenDecoderError.new("Token has expired", code: "expired_token"))
    end

    it "returns 401 Unauthorized" do
      # Validates that expired token triggers 401 response with expiration message
      header "Authorization", "Bearer expired.token"
      get "/"
      expect(last_response.status).to eq 401
      json = JSON.parse(last_response.body)
      expect(json["error"]).to eq("expired_token")
      expect(json["message"]).to match(/expired/i)
      expect(last_response.headers["WWW-Authenticate"]).to match(/error="expired_token"/)
    end
  end

  context "when kid rotates and first decode fails" do
    it "refreshes JWKS and retries once successfully" do
      # First call to decode! fails with kid-miss, second call succeeds
      first_error = Verikloak::TokenDecoderError.new("Key with kid=abc not found in JWKS", code: "invalid_token")
      expect(decoder).to receive(:decode!).and_raise(first_error).ordered
      expect(decoder).to receive(:decode!).and_return({ "sub" => "user2" }).ordered

      # Ensure JWKS is fetched twice: initial ensure_jwks_cache! + refresh_jwks! on retry
      expect_any_instance_of(Verikloak::JwksCache).to receive(:fetch!).twice.and_return(true)

      header "Authorization", "Bearer rotated.token"
      get "/"
      expect(last_response.status).to eq 200
      expect(last_request.env["verikloak.user"]).to eq({ "sub" => "user2" })
    end
  end

  context "when JWKS cache is empty" do
    # Test scenario: JWKS cache is empty, token validation cannot proceed, middleware rejects request
    before do
      allow_any_instance_of(Verikloak::JwksCache).to receive(:cached).and_return([])
      allow(decoder).to receive(:decode!).and_return({ "sub" => "user1" }) # This will not be called since JWKS cache is empty
    end

    it "returns 503 Service Unavailable" do
      # Checks that empty JWKS cache causes 503 with appropriate error message
      header "Authorization", "Bearer any.token"
      get "/"
      expect(last_response.status).to eq 503
      json = JSON.parse(last_response.body)
      expect(json["error"]).to eq("jwks_cache_miss")
      expect(json["message"]).to match(/JWKS cache is empty/i)
      expect(last_response.headers).not_to have_key("WWW-Authenticate")
    end
  end

  context "jwks fetching behavior" do
    before do
      allow(decoder).to receive(:decode!).and_return({ "sub" => "ok" })
      allow_any_instance_of(Verikloak::JwksCache).to receive(:cached).and_return([{ "kid" => "dummy" }])
    end

    it "calls fetch! on every request (even if cache appears fresh)" do
      # We issue two requests and expect fetch! to be called twice
      expect_any_instance_of(Verikloak::JwksCache).to receive(:fetch!).twice.and_return(true)

      header "Authorization", "Bearer token1"
      get "/"
      expect(last_response.status).to eq 200

      header "Authorization", "Bearer token2"
      get "/"
      expect(last_response.status).to eq 200
    end
  end

  context "option passthrough and decoder reuse" do
    let(:decoder) { instance_double("Verikloak::TokenDecoder") }
  
    before do
      allow(Verikloak::TokenDecoder).to receive(:new).and_return(decoder)
      allow(decoder).to receive(:decode!).and_return({ "sub" => "ok" })
      allow_any_instance_of(Verikloak::JwksCache).to receive(:cached).and_return([{ "kid" => "dummy" }])
      # Keep fetched_at constant to allow decoder cache reuse
      fixed_time = Time.now
      allow_any_instance_of(Verikloak::JwksCache).to receive(:fetched_at).and_return(fixed_time)
      allow_any_instance_of(Verikloak::JwksCache).to receive(:fetch!).and_return(true)
    end
  
    it "passes leeway and token_verify_options to TokenDecoder.new" do
      custom_mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        leeway: 15,
        token_verify_options: { verify_iat: false, leeway: 5 }
      )
  
      # Expect the constructor to receive merged options including our overrides
      expect(Verikloak::TokenDecoder).to receive(:new).with(
        hash_including(
          jwks: kind_of(Array),
          issuer: "https://example.com/",
          audience: "my-client-id",
          leeway: 15,
          options: hash_including(verify_iat: false, leeway: 5)
        )
      ).and_return(decoder)
  
      request = Rack::MockRequest.new(custom_mw)
      request.get("/", "HTTP_AUTHORIZATION" => "Bearer abc.def.ghi")
    end
  
    it "reuses TokenDecoder instance when JWKS is unchanged (same fetched_at)" do
      # With constant fetched_at, TokenDecoder.new should be called once for multiple requests
      expect(Verikloak::TokenDecoder).to receive(:new).once.and_return(decoder)
  
      header "Authorization", "Bearer token1"
      get "/"
      expect(last_response.status).to eq 200
  
      header "Authorization", "Bearer token2"
      get "/"
      expect(last_response.status).to eq 200
    end
  
    it "rebuilds TokenDecoder when JWKS fetched_at changes" do
      allow_any_instance_of(Verikloak::JwksCache).to receive(:fetch!).and_return(true)
      t0 = Time.now
      t1 = t0 + 1
      # fetched_at changes between requests → decoder cache invalidated
      allow_any_instance_of(Verikloak::JwksCache).to receive(:fetched_at).and_return(t0, t1)
      allow_any_instance_of(Verikloak::JwksCache).to receive(:cached).and_return([{ "kid" => "dummy" }])
  
      expect(Verikloak::TokenDecoder).to receive(:new).twice.and_return(decoder)
  
      header "Authorization", "Bearer tokenA"
      get "/"
      expect(last_response.status).to eq 200
  
      header "Authorization", "Bearer tokenB"
      get "/"
      expect(last_response.status).to eq 200
    end
  end
  
  context "connection injection to JWKS cache" do
    it "passes injected Faraday connection into JwksCache.new" do
      conn = Faraday.new
      # Verify that our connection object is passed into JwksCache.new by middleware
      expect(Verikloak::JwksCache).to receive(:new).with(
        hash_including(jwks_uri: "https://example.com/jwks", connection: conn)
      ).and_call_original
  
      custom_mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        connection: conn
      )
  
      allow_any_instance_of(Verikloak::JwksCache).to receive(:cached).and_return([{ "kid" => "dummy" }])
      allow_any_instance_of(Verikloak::JwksCache).to receive(:fetch!).and_return(true)
      allow(Verikloak::TokenDecoder).to receive(:new).and_return(instance_double("Verikloak::TokenDecoder", decode!: { "sub" => "ok" }))
  
      request = Rack::MockRequest.new(custom_mw)
      res = request.get("/", "HTTP_AUTHORIZATION" => "Bearer abc.def.ghi")
      expect(res.status).to eq 200
    end
  end

  context "skip_paths wildcard behavior" do
    it "skips exactly '/' when skip_paths includes only '/'" do
      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        skip_paths: ['/']
      )
      request = Rack::MockRequest.new(mw)

      # Root is skipped (no auth required)
      res = request.get("/")
      expect(res.status).to eq 200
      expect(res["WWW-Authenticate"]).to be_nil

      # Non-root still requires auth and returns 401 when header is missing
      res2 = request.get("/not-root")
      expect(res2.status).to eq 401
      expect(res2["WWW-Authenticate"]).to match(/Bearer/)
    end

    it "skips a prefix and all of its subpaths when listed with /* in skip_paths" do
      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        skip_paths: ['/', '/rails/*', '/public/src'] # '/rails/*' matches '/rails' and '/rails/...'
      )
      request = Rack::MockRequest.new(mw)

      res1 = request.get("/")
      res2 = request.get("/rails")
      res3 = request.get("/rails/api/v1/notes")
      res4 = request.get("/public/src")

      [res1, res2, res3, res4].each do |r|
        expect(r.status).to eq 200
        expect(r["WWW-Authenticate"]).to be_nil
      end

      # A nearby but different prefix is not skipped
      res5 = request.get("/public/health")
      res6 = request.get("/public/src/html")
      res7 = request.get("/pub")
      [res5, res6, res7].each do |r|
        expect(r.status).to eq 401
        expect(r["WWW-Authenticate"]).to match(/Bearer/)
      end
    end
  end

  context "WWW-Authenticate header details" do
    it "includes Bearer error and description when Authorization header is missing" do
      header "Authorization", nil
      get "/"
      expect(last_response.status).to eq 401
      www = last_response.headers["WWW-Authenticate"]
      expect(www).to include("Bearer")
      expect(www).to include('error="missing_authorization_header"')
      expect(www).to match(/error_description="[^"]+"/)
    end

    it "includes Bearer error and description for invalid token" do
      allow(decoder).to receive(:decode!)
        .and_raise(Verikloak::TokenDecoderError.new("JWT decode failed", code: "invalid_token"))

      header "Authorization", "Bearer bad.token"
      get "/"
      expect(last_response.status).to eq 401
      www = last_response.headers["WWW-Authenticate"]
      expect(www).to include("Bearer")
      expect(www).to include('error="invalid_token"')
      expect(www).to include('error_description="JWT decode failed"')
    end
  end

  context "token_verify_options influencing outcome" do
    it "returns 401 normally for expired token but 200 when verify_expiration: false is provided" do
      # Build two middleware instances: default (should 401) and relaxed (should 200)
      default_mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id"
      )
      relaxed_mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        token_verify_options: { verify_expiration: false }
      )

      # Discovery and JWKS behave the same for both
      allow_any_instance_of(Verikloak::Discovery).to receive(:fetch!)
        .and_return({ "issuer" => "https://example.com/", "jwks_uri" => "https://example.com/jwks" })
      allow_any_instance_of(Verikloak::JwksCache).to receive(:fetch!).and_return(true)
      allow_any_instance_of(Verikloak::JwksCache).to receive(:cached).and_return([{"kid" => "dummy"}])

      # TokenDecoder.new should receive options; based on options, we return different doubles
      allow(Verikloak::TokenDecoder).to receive(:new) do |args|
        if args[:options].is_a?(Hash) && args[:options][:verify_expiration] == false
          instance_double("Verikloak::TokenDecoder", decode!: { "sub" => "ok" })
        else
          err = Verikloak::TokenDecoderError.new("Token has expired", code: "expired_token")
          instance_double("Verikloak::TokenDecoder").tap do |d|
            allow(d).to receive(:decode!).and_raise(err)
          end
        end
      end

      # Default: 401 expired
      res1 = Rack::MockRequest.new(default_mw).get("/", "HTTP_AUTHORIZATION" => "Bearer expired")
      expect(res1.status).to eq 401
      expect(res1["WWW-Authenticate"]).to include('error="expired_token"')

      # Relaxed: 200 OK because verify_expiration: false is applied
      res2 = Rack::MockRequest.new(relaxed_mw).get("/", "HTTP_AUTHORIZATION" => "Bearer expired")
      expect(res2.status).to eq 200
      expect(res2["WWW-Authenticate"]).to be_nil
    end
  end
end