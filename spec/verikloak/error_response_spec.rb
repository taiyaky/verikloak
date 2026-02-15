# frozen_string_literal: true

require "spec_helper"
require "verikloak/error_response"

RSpec.describe Verikloak::ErrorResponse do
  describe ".build" do
    it "returns a Rack response triple" do
      status, headers, body = described_class.build(
        code: "test_error", message: "Something went wrong", status: 400
      )

      expect(status).to eq 400
      expect(headers["Content-Type"]).to eq("application/json")

      json = JSON.parse(body.first)
      expect(json["error"]).to eq("test_error")
      expect(json["message"]).to eq("Something went wrong")
    end

    it "includes WWW-Authenticate header for 401 responses" do
      status, headers, = described_class.build(
        code: "invalid_token", message: "Token has expired", status: 401
      )

      expect(status).to eq 401
      expect(headers["WWW-Authenticate"]).to include('Bearer realm="verikloak"')
      expect(headers["WWW-Authenticate"]).to include('error="invalid_token"')
      expect(headers["WWW-Authenticate"]).to include('error_description="Token has expired"')
    end

    it "uses custom realm in WWW-Authenticate" do
      _, headers, = described_class.build(
        code: "unauthorized", message: "No token", status: 401, realm: "my-api"
      )

      expect(headers["WWW-Authenticate"]).to include('realm="my-api"')
    end

    it "does NOT include WWW-Authenticate for non-401 responses" do
      _, headers, = described_class.build(
        code: "forbidden", message: "Access denied", status: 403
      )

      expect(headers).not_to have_key("WWW-Authenticate")
    end
  end

  describe ".sanitize_header_value" do
    it "strips CR/LF characters to prevent header injection" do
      # A malicious value with CRLF could inject a new header line
      malicious = "legit\r\nX-Injected: evil"
      result = described_class.sanitize_header_value(malicious)

      expect(result).not_to include("\r")
      expect(result).not_to include("\n")
      expect(result).to include("legit")
    end

    it "strips lone CR and lone LF" do
      expect(described_class.sanitize_header_value("a\rb\nc")).to eq("a b c")
    end

    it "escapes double-quotes" do
      result = described_class.sanitize_header_value('say "hello"')
      expect(result).to eq('say \\"hello\\"')
    end

    it "escapes backslashes" do
      result = described_class.sanitize_header_value('path\\to\\file')
      expect(result).to eq('path\\\\to\\\\file')
    end

    it "strips control characters" do
      result = described_class.sanitize_header_value("hello\x00world\x1F!")
      expect(result).to eq("helloworld!")
    end

    it "handles nil gracefully" do
      expect(described_class.sanitize_header_value(nil)).to eq("")
    end

    it "prevents full CRLF header injection in a 401 response" do
      # Scenario: attacker injects a cookie via error code containing CRLF
      malicious_code = "bad\r\nSet-Cookie: evil=true\r\nX-Pwned: yes"
      _, headers, = described_class.build(
        code: malicious_code, message: "test", status: 401
      )

      www_auth = headers["WWW-Authenticate"]
      expect(www_auth).not_to include("Set-Cookie")
      expect(www_auth).not_to include("X-Pwned")
      expect(www_auth).not_to include("\r")
      expect(www_auth).not_to include("\n")
    end
  end
end
