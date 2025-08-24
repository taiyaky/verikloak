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
end
