# frozen_string_literal: true

# Tests for security hardening features added in v0.4.0:
# - JWT size limit (MAX_TOKEN_BYTES)
# - HTTP scheme enforcement (allow_http)

require "rack/test"
require "verikloak"

RSpec.describe "Verikloak::Middleware security hardening" do
  include Rack::Test::Methods

  let(:inner_app) do
    ->(env) { [200, { "Content-Type" => "text/plain" }, ["OK"]] }
  end

  let(:decoder) { instance_double("Verikloak::TokenDecoder") }

  describe "JWT size limit" do
    before do
      allow_any_instance_of(Verikloak::Discovery).to receive(:fetch!)
        .and_return({ "issuer" => "https://example.com/", "jwks_uri" => "https://example.com/jwks" })
      allow_any_instance_of(Verikloak::JwksCache).to receive(:fetch!).and_return(true)
      allow_any_instance_of(Verikloak::JwksCache).to receive(:cached).and_return([{ "kid" => "dummy" }])
      allow(Verikloak::TokenDecoder).to receive(:new).and_return(decoder)
      allow(decoder).to receive(:decode!).and_return({ "sub" => "user1" })
    end
    let(:middleware) do
      Verikloak::Middleware.new(inner_app,
        discovery_url: "https://example.com/.well-known/openid-configuration",
        audience: "my-client-id")
    end

    def app
      middleware
    end

    it "accepts a token within the size limit" do
      token = "a" * 1000
      header "Authorization", "Bearer #{token}"
      get "/"
      # Token is syntactically valid (just a string), decoder is mocked
      expect(last_response.status).to eq 200
    end

    it "rejects a token exceeding MAX_TOKEN_BYTES (8192)" do
      oversized_token = "a" * 8193
      header "Authorization", "Bearer #{oversized_token}"
      get "/"
      expect(last_response.status).to eq 401
      json = JSON.parse(last_response.body)
      expect(json["error"]).to eq("invalid_token")
      expect(json["message"]).to match(/maximum allowed size/i)
    end

    it "accepts a token at exactly the boundary (8192 bytes)" do
      boundary_token = "a" * 8192
      header "Authorization", "Bearer #{boundary_token}"
      get "/"
      expect(last_response.status).to eq 200
    end
  end

  describe "HTTP scheme enforcement" do
    it "raises DiscoveryError for http:// discovery URL by default" do
      expect {
        Verikloak::Discovery.new(discovery_url: "http://insecure.example.com/.well-known/openid-configuration")
      }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.code).to eq("insecure_discovery_url")
        expect(e.message).to match(/HTTPS/i)
      }
    end

    it "allows http:// when allow_http: true is set" do
      stub_request(:get, "http://dev.local/.well-known/openid-configuration").to_return(
        status: 200,
        body: { jwks_uri: "http://dev.local/jwks", issuer: "http://dev.local/" }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

      discovery = Verikloak::Discovery.new(
        discovery_url: "http://dev.local/.well-known/openid-configuration",
        allow_http: true
      )
      json = discovery.fetch!
      expect(json["issuer"]).to eq("http://dev.local/")
    end

    it "always allows https:// URLs" do
      stub_request(:get, "https://secure.example.com/.well-known/openid-configuration").to_return(
        status: 200,
        body: { jwks_uri: "https://secure.example.com/jwks", issuer: "https://secure.example.com/" }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

      discovery = Verikloak::Discovery.new(
        discovery_url: "https://secure.example.com/.well-known/openid-configuration"
      )
      json = discovery.fetch!
      expect(json["issuer"]).to eq("https://secure.example.com/")
    end
  end

  describe "SSRF redirect protection" do
    let(:discovery_url) { "https://example.com/.well-known/openid-configuration" }

    it "blocks redirects to private IP (10.x.x.x)" do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://internal.example.com/config" }
      )
      allow(Resolv).to receive(:getaddresses).with("internal.example.com").and_return(["10.0.0.1"])

      discovery = Verikloak::Discovery.new(discovery_url: discovery_url)
      expect { discovery.fetch! }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.code).to eq("discovery_redirect_error")
        expect(e.message).to match(/private.*internal/i)
      }
    end

    it "blocks redirects to loopback (127.x.x.x)" do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://localhost/config" }
      )
      allow(Resolv).to receive(:getaddresses).with("localhost").and_return(["127.0.0.1"])

      discovery = Verikloak::Discovery.new(discovery_url: discovery_url)
      expect { discovery.fetch! }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.code).to eq("discovery_redirect_error")
        expect(e.message).to match(/private.*internal/i)
      }
    end

    it "blocks redirects to 192.168.x.x" do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://intranet.local/config" }
      )
      allow(Resolv).to receive(:getaddresses).with("intranet.local").and_return(["192.168.1.1"])

      discovery = Verikloak::Discovery.new(discovery_url: discovery_url)
      expect { discovery.fetch! }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.code).to eq("discovery_redirect_error")
      }
    end

    it "allows redirects to public IPs" do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://cdn.example.com/config" }
      )
      stub_request(:get, "https://cdn.example.com/config").to_return(
        status: 200,
        body: { jwks_uri: "https://cdn.example.com/jwks", issuer: "https://cdn.example.com/" }.to_json,
        headers: { "Content-Type" => "application/json" }
      )
      allow(Resolv).to receive(:getaddresses).with("cdn.example.com").and_return(["93.184.216.34"])

      discovery = Verikloak::Discovery.new(discovery_url: discovery_url)
      json = discovery.fetch!
      expect(json["issuer"]).to eq("https://cdn.example.com/")
    end

    it "blocks redirects to IPv6 loopback (::1)" do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://ipv6.local/config" }
      )
      allow(Resolv).to receive(:getaddresses).with("ipv6.local").and_return(["::1"])

      discovery = Verikloak::Discovery.new(discovery_url: discovery_url)
      expect { discovery.fetch! }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.code).to eq("discovery_redirect_error")
      }
    end

    it "blocks redirects that downgrade from HTTPS to HTTP" do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "http://evil.example.com/config" }
      )

      discovery = Verikloak::Discovery.new(discovery_url: discovery_url)
      expect { discovery.fetch! }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.code).to eq("discovery_redirect_error")
        expect(e.message).to match(/HTTPS/i)
      }
    end

    it "allows HTTP redirect targets when allow_http: true" do
      stub_request(:get, "http://dev.local/.well-known/openid-configuration").to_return(
        status: 302,
        headers: { "Location" => "http://dev.local/config" }
      )
      stub_request(:get, "http://dev.local/config").to_return(
        status: 200,
        body: { jwks_uri: "http://dev.local/jwks", issuer: "http://dev.local/" }.to_json,
        headers: { "Content-Type" => "application/json" }
      )
      allow(Resolv).to receive(:getaddresses).with("dev.local").and_return(["93.184.216.34"])

      discovery = Verikloak::Discovery.new(
        discovery_url: "http://dev.local/.well-known/openid-configuration",
        allow_http: true
      )
      json = discovery.fetch!
      expect(json["issuer"]).to eq("http://dev.local/")
    end

    it "blocks redirects with non-HTTP(S) schemes (e.g. ftp://)" do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "ftp://evil.example.com/config" }
      )

      discovery = Verikloak::Discovery.new(discovery_url: discovery_url)
      expect { discovery.fetch! }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.code).to eq("discovery_redirect_error")
        expect(e.message).to match(/unsupported scheme/i)
      }
    end

    it "blocks redirects to IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)" do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://mapped.example.com/config" }
      )
      allow(Resolv).to receive(:getaddresses).with("mapped.example.com").and_return(["::ffff:127.0.0.1"])

      discovery = Verikloak::Discovery.new(discovery_url: discovery_url)
      expect { discovery.fetch! }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.code).to eq("discovery_redirect_error")
        expect(e.message).to match(/private.*internal/i)
      }
    end

    it "blocks redirects to IPv4-mapped IPv6 private address (::ffff:10.0.0.1)" do
      stub_request(:get, discovery_url).to_return(
        status: 302,
        headers: { "Location" => "https://mapped-private.example.com/config" }
      )
      allow(Resolv).to receive(:getaddresses).with("mapped-private.example.com").and_return(["::ffff:10.0.0.1"])

      discovery = Verikloak::Discovery.new(discovery_url: discovery_url)
      expect { discovery.fetch! }.to raise_error(Verikloak::DiscoveryError) { |e|
        expect(e.code).to eq("discovery_redirect_error")
        expect(e.message).to match(/private.*internal/i)
      }
    end
  end

  describe "URL normalization (strip whitespace)" do
    it "strips leading/trailing whitespace from discovery_url" do
      padded_url = "  https://secure.example.com/.well-known/openid-configuration  "
      stub_request(:get, "https://secure.example.com/.well-known/openid-configuration").to_return(
        status: 200,
        body: { jwks_uri: "https://secure.example.com/jwks", issuer: "https://secure.example.com/" }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

      discovery = Verikloak::Discovery.new(discovery_url: padded_url)
      json = discovery.fetch!
      expect(json["issuer"]).to eq("https://secure.example.com/")
    end

    it "strips leading/trailing whitespace from jwks_uri" do
      padded_uri = "  https://example.com/jwks  "
      cache = Verikloak::JwksCache.new(jwks_uri: padded_uri)
      # Ensure the stored URI is stripped (it will be used for HTTP requests)
      expect(cache.instance_variable_get(:@jwks_uri)).to eq("https://example.com/jwks")
    end
  end
end
