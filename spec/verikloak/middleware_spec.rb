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

    # Mock the JWKs cache
    allow_any_instance_of(Verikloak::JwksCache).to receive(:fetch!).and_return(true)
    allow_any_instance_of(Verikloak::JwksCache).to receive(:cached).and_return([{"kid" => "dummy"}])

    # Replace all TokenDecoder.new calls with this decoder instance
    allow(Verikloak::TokenDecoder).to receive(:new).and_return(decoder)
  end

  context "configuration knobs" do
    before do
      allow(decoder).to receive(:decode!).and_return({ "sub" => "user1" })
    end

    it "allows customizing env keys for user and token" do
      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        token_env_key: "custom.token",
        user_env_key: "custom.user"
      )

      token_value = "mytesttoken123"
      env = Rack::MockRequest.env_for("/", "HTTP_AUTHORIZATION" => "Bearer #{token_value}")
      status, = mw.call(env)

      expect(status).to eq 200
      expect(env["custom.user"]).to eq({ "sub" => "user1" })
      expect(env["custom.token"]).to eq(token_value)
    end

    it "allows customizing the WWW-Authenticate realm" do
      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        realm: "api.example"
      )

      status, headers, = mw.call(Rack::MockRequest.env_for("/"))

      expect(status).to eq 401
      expect(headers["WWW-Authenticate"]).to include("realm=\"api.example\"")
    end

    it "logs unexpected errors to injected logger" do
      failing_app = ->(_env) { raise "boom" }
      allow(decoder).to receive(:decode!).and_return({ "sub" => "user1" })
      logger = double("Logger")
      expect(logger).to receive(:error)
        .with(a_string_including("[verikloak] Internal error: RuntimeError - boom"))
      expect(logger).to receive(:error)
        .with(a_string_matching(/middleware_spec\.rb:\d+/))

      mw = described_class.new(failing_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        logger: logger
      )

      env = Rack::MockRequest.env_for("/", "HTTP_AUTHORIZATION" => "Bearer token")
      status, headers, body = mw.call(env)

      expect(status).to eq 500
      expect(headers["Content-Type"]).to eq("application/json")
      expect(body.join).to include("internal_server_error")
    end

    it "raises when token_env_key is blank" do
      expect do
        described_class.new(inner_app,
          discovery_url: "https://example.com/.well-known/openid-configuration",
          audience: "my-client-id",
          token_env_key: " \t ")
      end.to raise_error(ArgumentError, "token_env_key cannot be blank")
    end

    it "raises when user_env_key is blank" do
      expect do
        described_class.new(inner_app,
          discovery_url: "https://example.com/.well-known/openid-configuration",
          audience: "my-client-id",
          user_env_key: "")
      end.to raise_error(ArgumentError, "user_env_key cannot be blank")
    end

    it "raises when realm is blank" do
      expect do
        described_class.new(inner_app,
          discovery_url: "https://example.com/.well-known/openid-configuration",
          audience: "my-client-id",
          realm: " ")
      end.to raise_error(ArgumentError, "realm cannot be blank")
    end
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
      expect(last_request.env["verikloak.token"]).to eq("valid.token")
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
    it "refreshes JWKs and retries once successfully" do
      # First call to decode! fails with kid-miss, second call succeeds
      first_error = Verikloak::TokenDecoderError.new("Key with kid=abc not found in JWKs", code: "invalid_token")
      expect(decoder).to receive(:decode!).and_raise(first_error).ordered
      expect(decoder).to receive(:decode!).and_return({ "sub" => "user2" }).ordered

      # Ensure JWKs is fetched twice: initial ensure_jwks_cache! + refresh_jwks! on retry
      expect_any_instance_of(Verikloak::JwksCache).to receive(:fetch!).twice.and_return(true)

      header "Authorization", "Bearer rotated.token"
      get "/"
      expect(last_response.status).to eq 200
      expect(last_request.env["verikloak.user"]).to eq({ "sub" => "user2" })
    end
  end

  context "when JWKs cache is empty" do
    # Test scenario: JWKs cache is empty, token validation cannot proceed, middleware rejects request
    before do
      allow_any_instance_of(Verikloak::JwksCache).to receive(:cached).and_return([])
      allow(decoder).to receive(:decode!).and_return({ "sub" => "user1" }) # This will not be called since JWKs cache is empty
    end

    it "returns 503 Service Unavailable" do
      # Checks that empty JWKs cache causes 503 with appropriate error message
      header "Authorization", "Bearer any.token"
      get "/"
      expect(last_response.status).to eq 503
      json = JSON.parse(last_response.body)
      expect(json["error"]).to eq("jwks_cache_miss")
      expect(json["message"]).to match(/JWKs cache is empty/i)
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
  
    it "reuses TokenDecoder instance when JWKs is unchanged (same fetched_at)" do
      # With constant fetched_at, TokenDecoder.new should be called once for multiple requests
      expect(Verikloak::TokenDecoder).to receive(:new).once.and_return(decoder)
  
      header "Authorization", "Bearer token1"
      get "/"
      expect(last_response.status).to eq 200
  
      header "Authorization", "Bearer token2"
      get "/"
      expect(last_response.status).to eq 200
    end
  
    it "rebuilds TokenDecoder when JWKs fetched_at changes" do
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
  
  context "connection injection to JWKs cache" do
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

  context "audience callable arity handling" do
    it "supports zero-arity callables without passing env" do
      zero_callable = double("ZeroAudience")
      expect(zero_callable).to receive(:call).with(no_args).and_return("zero-client")
      
      # Mock method(:call).parameters to return empty array for zero-arity
      call_method = double("CallMethod")
      allow(call_method).to receive(:parameters).and_return([])
      allow(zero_callable).to receive(:method).with(:call).and_return(call_method)

      allow(decoder).to receive(:decode!).and_return({ "sub" => "ok" })

      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: zero_callable
      )

      request = Rack::MockRequest.new(mw)
      response = request.get("/profile", "HTTP_AUTHORIZATION" => "Bearer token")

      expect(response.status).to eq 200
    end

    it "falls back when callable hides arity and rejects env argument" do
      methodless_class = Class.new(BasicObject) do
        def initialize(value)
          @value = value
          @calls = []
        end

        def call(*args)
          @calls << args
          if args.any?
            ::Kernel.raise ::ArgumentError, "wrong number of arguments (given #{args.length}, expected 0)"
          end
          @value
        end

        def calls
          @calls
        end

        def respond_to?(name, include_private = false)
          name == :call || name == :respond_to? || name == :calls
        end

        def respond_to_missing?(name, include_private = false)
          name == :call || name == :respond_to? || name == :calls
        end
      end

      callable = methodless_class.new("methodless-client")

      allow(decoder).to receive(:decode!).and_return({ "sub" => "ok" })

      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: callable
      )

      request = Rack::MockRequest.new(mw)
      response = request.get("/dashboard", "HTTP_AUTHORIZATION" => "Bearer token")

      expect(response.status).to eq 200
      expect(callable.calls.length).to eq(2)
      first_args = callable.calls.first
      expect(first_args.length).to eq(1)
      expect(first_args.first).to be_a(::Hash)
      expect(callable.calls.last).to eq([])
    end

    it "supports keyword-only audience callables" do
      keyword_callable = Class.new do
        attr_reader :calls

        def initialize
          @calls = []
        end

        def call(env:)
          @calls << env
          "keyword-client"
        end
      end.new

      allow(decoder).to receive(:decode!).and_return({ "sub" => "ok" })

      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: keyword_callable
      )

      request = Rack::MockRequest.new(mw)
      response = request.get("/keyword", "HTTP_AUTHORIZATION" => "Bearer token")

      expect(response.status).to eq 200
      expect(keyword_callable.calls.length).to eq(1)
      expect(keyword_callable.calls.first).to be_a(Hash)
      expect(keyword_callable.calls.first["PATH_INFO"]).to eq("/keyword")
    end
  end

  context "dynamic audience resolution" do
    let(:audience_proc) do
      lambda do |env|
        env['PATH_INFO'] == '/admin' ? 'admin-client' : 'user-client'
      end
    end

    before do
      allow(Verikloak::TokenDecoder).to receive(:new).and_call_original
    end

    it "evaluates callable per request and caches decoders per audience" do
      decoder_user = instance_double("Verikloak::TokenDecoder")
      decoder_admin = instance_double("Verikloak::TokenDecoder")
      allow(decoder_user).to receive(:decode!).and_return({ "sub" => "user" })
      allow(decoder_admin).to receive(:decode!).and_return({ "sub" => "admin" })

      expect(Verikloak::TokenDecoder).to receive(:new)
        .with(hash_including(audience: 'user-client'))
        .once
        .and_return(decoder_user)
      expect(Verikloak::TokenDecoder).to receive(:new)
        .with(hash_including(audience: 'admin-client'))
        .once
        .and_return(decoder_admin)

      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: audience_proc
      )

      request = Rack::MockRequest.new(mw)
      res_user = request.get("/profile", "HTTP_AUTHORIZATION" => "Bearer token-user")
      expect(res_user.status).to eq 200

      res_admin = request.get("/admin", "HTTP_AUTHORIZATION" => "Bearer token-admin")
      expect(res_admin.status).to eq 200

      res_user_again = request.get("/profile", "HTTP_AUTHORIZATION" => "Bearer token-user-2")
      expect(res_user_again.status).to eq 200
    end

    it "returns 401 when callable resolves to blank audience" do
      blank_proc = ->(_env) { "" }
      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: blank_proc
      )

      request = Rack::MockRequest.new(mw)
      response = request.get("/profile", "HTTP_AUTHORIZATION" => "Bearer token")

      expect(response.status).to eq 401
      body = JSON.parse(response.body)
      expect(body["error"]).to eq("invalid_audience")
      expect(body["message"]).to match(/Audience is blank/)
    end
  end

  context "decoder cache management" do
    let(:decoder_instances) { Hash.new { |hash, key| hash[key] = [] } }

    before do
      allow(Verikloak::TokenDecoder).to receive(:new) do |options|
        instance = instance_double("Verikloak::TokenDecoder")
        decoder_instances[options[:audience]] << instance
        allow(instance).to receive(:decode!).and_return({ "sub" => options[:audience] })
        instance
      end
    end

    it "evicts least recently used decoders when limit is exceeded" do
      cache = Class.new do
        attr_reader :fetched_at

        def initialize(keys)
          @keys = keys
          @fetched_at = Time.now
        end

        def cached
          @keys
        end

        def fetch!
          @fetched_at ||= Time.now
          @keys
        end
      end.new([{ "kid" => "limit" }])

      audience_proc = lambda do |env|
        env['PATH_INFO'].delete_prefix('/')
      end

      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: audience_proc,
        jwks_cache: cache,
        decoder_cache_limit: 2
      )

      request = Rack::MockRequest.new(mw)

      %w[a1 a2 a3 a1].each do |aud|
        response = request.get("/#{aud}", "HTTP_AUTHORIZATION" => "Bearer token-#{aud}")
        expect(response.status).to eq 200
      end

      expect(decoder_instances['a1'].size).to eq(2)
      expect(decoder_instances['a2'].size).to eq(1)
      expect(decoder_instances['a3'].size).to eq(1)
    end

    it "clears cached decoders when JWK keys rotate" do
      rotating_cache = Class.new do
        attr_reader :fetched_at

        def initialize(keys)
          @keys = keys
          @fetched_at = Time.now
        end

        def cached
          @keys
        end

        def fetch!
          @fetched_at ||= Time.now
          @keys
        end

        def rotate!(new_keys)
          @keys = new_keys
          @fetched_at = Time.now
        end
      end.new([{ "kid" => "v1" }])

      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        jwks_cache: rotating_cache,
        decoder_cache_limit: nil
      )

      request = Rack::MockRequest.new(mw)

      response_first = request.get("/initial", "HTTP_AUTHORIZATION" => "Bearer token-initial")
      expect(response_first.status).to eq 200
      expect(decoder_instances['my-client-id'].size).to eq(1)
      expect(mw.instance_variable_get(:@decoder_cache).size).to eq(1)

      rotating_cache.rotate!([{ "kid" => "v2" }])

      response_second = request.get("/rotated", "HTTP_AUTHORIZATION" => "Bearer token-rotated")
      expect(response_second.status).to eq 200
      expect(decoder_instances['my-client-id'].size).to eq(2)
      expect(mw.instance_variable_get(:@decoder_cache).size).to eq(1)
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

      # Discovery and JWKs behave the same for both
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

  context "issuer parameter configuration" do
    # Test scenario: issuer parameter overrides discovery issuer for JWT verification
    let(:discovery_issuer) { "https://discovery.example.com/" }
    let(:custom_issuer) { "https://custom.example.com/" }

    before do
      allow_any_instance_of(Verikloak::Discovery).to receive(:fetch!)
        .and_return({ "issuer" => discovery_issuer, "jwks_uri" => "https://example.com/jwks" })
      allow_any_instance_of(Verikloak::JwksCache).to receive(:fetch!).and_return(true)
      allow_any_instance_of(Verikloak::JwksCache).to receive(:cached).and_return([{"kid" => "dummy"}])
    end

    it "uses discovery issuer when issuer parameter is not provided" do
      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id"
      )

      expect(Verikloak::TokenDecoder).to receive(:new).with(
        hash_including(issuer: discovery_issuer)
      ).and_return(instance_double("Verikloak::TokenDecoder", decode!: { "sub" => "user1" }))

      request = Rack::MockRequest.new(mw)
      res = request.get("/", "HTTP_AUTHORIZATION" => "Bearer token")
      expect(res.status).to eq 200
    end

    it "uses configured issuer when issuer parameter is provided" do
      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        issuer: custom_issuer
      )

      expect(Verikloak::TokenDecoder).to receive(:new).with(
        hash_including(issuer: custom_issuer)
      ).and_return(instance_double("Verikloak::TokenDecoder", decode!: { "sub" => "user1" }))

      request = Rack::MockRequest.new(mw)
      res = request.get("/", "HTTP_AUTHORIZATION" => "Bearer token")
      expect(res.status).to eq 200
    end

    it "configured issuer takes precedence over discovery issuer" do
      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        issuer: custom_issuer
      )

      # Verify that the custom issuer is used, not the discovery one
      expect(Verikloak::TokenDecoder).to receive(:new) do |args|
        expect(args[:issuer]).to eq(custom_issuer)
        expect(args[:issuer]).not_to eq(discovery_issuer)
        instance_double("Verikloak::TokenDecoder", decode!: { "sub" => "user1" })
      end

      request = Rack::MockRequest.new(mw)
      res = request.get("/", "HTTP_AUTHORIZATION" => "Bearer token")
      expect(res.status).to eq 200
    end

    it "uses configured issuer when jwks_cache is injected" do
      # Create a mock JwksCache that behaves like a pre-existing cache
      mock_jwks_cache = instance_double("Verikloak::JwksCache")
      allow(mock_jwks_cache).to receive(:fetch!).and_return(true)
      allow(mock_jwks_cache).to receive(:cached).and_return([{"kid" => "dummy"}])
      allow(mock_jwks_cache).to receive(:fetched_at).and_return(nil)

      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        issuer: custom_issuer,
        jwks_cache: mock_jwks_cache  # Pre-inject cache
      )

      # Even with injected cache, configured issuer should be used
      expect(Verikloak::TokenDecoder).to receive(:new).with(
        hash_including(issuer: custom_issuer)
      ).and_return(instance_double("Verikloak::TokenDecoder", decode!: { "sub" => "user1" }))

      request = Rack::MockRequest.new(mw)
      res = request.get("/", "HTTP_AUTHORIZATION" => "Bearer token")
      expect(res.status).to eq 200
    end

    it "uses discovery issuer when jwks_cache is injected but no issuer configured" do
      # Create a mock JwksCache that behaves like a pre-existing cache
      mock_jwks_cache = instance_double("Verikloak::JwksCache")
      allow(mock_jwks_cache).to receive(:fetch!).and_return(true)
      allow(mock_jwks_cache).to receive(:cached).and_return([{"kid" => "dummy"}])
      allow(mock_jwks_cache).to receive(:fetched_at).and_return(nil)

      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        jwks_cache: mock_jwks_cache  # Pre-inject cache, no issuer configured
      )

      # Should fetch discovery and use discovered issuer
      expect(Verikloak::TokenDecoder).to receive(:new).with(
        hash_including(issuer: discovery_issuer)
      ).and_return(instance_double("Verikloak::TokenDecoder", decode!: { "sub" => "user1" }))

      request = Rack::MockRequest.new(mw)
      res = request.get("/", "HTTP_AUTHORIZATION" => "Bearer token")
      expect(res.status).to eq 200
    end

    it "does not call discovery when both issuer and jwks_cache are provided" do
      # Create a mock JwksCache that behaves like a pre-existing cache
      mock_jwks_cache = instance_double("Verikloak::JwksCache")
      allow(mock_jwks_cache).to receive(:fetch!).and_return(true)
      allow(mock_jwks_cache).to receive(:cached).and_return([{"kid" => "dummy"}])
      allow(mock_jwks_cache).to receive(:fetched_at).and_return(nil)

      # Mock discovery to verify it's NOT called
      mock_discovery = instance_double("Verikloak::Discovery")
      
      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        issuer: custom_issuer,
        jwks_cache: mock_jwks_cache,  # Pre-inject cache
        discovery: mock_discovery     # Mock discovery
      )

      # Discovery should NOT be called when both issuer and jwks_cache are provided
      expect(mock_discovery).not_to receive(:fetch!)

      expect(Verikloak::TokenDecoder).to receive(:new).with(
        hash_including(issuer: custom_issuer)
      ).and_return(instance_double("Verikloak::TokenDecoder", decode!: { "sub" => "user1" }))

      request = Rack::MockRequest.new(mw)
      res = request.get("/", "HTTP_AUTHORIZATION" => "Bearer token")
      expect(res.status).to eq 200
    end

    it "calls discovery only once when jwks_cache is injected but no issuer configured" do
      # Create a mock JwksCache that behaves like a pre-existing cache
      mock_jwks_cache = instance_double("Verikloak::JwksCache")
      allow(mock_jwks_cache).to receive(:fetch!).and_return(true)
      allow(mock_jwks_cache).to receive(:cached).and_return([{"kid" => "dummy"}])
      allow(mock_jwks_cache).to receive(:fetched_at).and_return(nil)

      # Mock discovery to verify it's called only once
      mock_discovery = instance_double("Verikloak::Discovery")

      mw = described_class.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id",
        jwks_cache: mock_jwks_cache,  # Pre-inject cache, no issuer configured
        discovery: mock_discovery     # Mock discovery
      )

      # Discovery should be called only once (on first request), not on subsequent requests
      expect(mock_discovery).to receive(:fetch!).once.and_return({ "issuer" => discovery_issuer, "jwks_uri" => "https://example.com/jwks" })

      # TokenDecoder should be created only once and then cached for subsequent requests
      expect(Verikloak::TokenDecoder).to receive(:new).once.with(
        hash_including(issuer: discovery_issuer)
      ).and_return(instance_double("Verikloak::TokenDecoder", decode!: { "sub" => "user1" }))

      # First request - should trigger discovery
      request = Rack::MockRequest.new(mw)
      res = request.get("/", "HTTP_AUTHORIZATION" => "Bearer token")
      expect(res.status).to eq 200

      # Second request - should NOT trigger discovery again
      res = request.get("/", "HTTP_AUTHORIZATION" => "Bearer token")
      expect(res.status).to eq 200
    end
  end
end
