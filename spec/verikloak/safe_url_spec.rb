# This test suite verifies the shared URL normalization and SSRF helpers in Verikloak::SafeUrl.

# frozen_string_literal: true

require "spec_helper"

RSpec.describe Verikloak::SafeUrl do
  describe ".normalize" do
    it "strips surrounding whitespace from HTTP(S) URLs" do
      expect(described_class.normalize("  https://example.com/x \n")).to eq("https://example.com/x")
      expect(described_class.normalize("http://example.com")).to eq("http://example.com")
    end

    it "returns nil for non-string values" do
      expect(described_class.normalize(nil)).to be_nil
      expect(described_class.normalize(123)).to be_nil
      expect(described_class.normalize(URI.parse("https://example.com"))).to be_nil
    end

    it "returns nil for non-HTTP(S) schemes and garbage" do
      expect(described_class.normalize("ftp://example.com")).to be_nil
      expect(described_class.normalize("not a url")).to be_nil
      expect(described_class.normalize("")).to be_nil
    end
  end

  describe ".insecure_http?" do
    it "flags plain HTTP when allow_http is false" do
      expect(described_class.insecure_http?("http://example.com", allow_http: false)).to be true
    end

    it "allows plain HTTP when allow_http is true" do
      expect(described_class.insecure_http?("http://example.com", allow_http: true)).to be false
    end

    it "always allows HTTPS" do
      expect(described_class.insecure_http?("https://example.com", allow_http: false)).to be false
    end
  end

  describe ".resolves_to_private_ip?" do
    it "returns false for blank hosts" do
      expect(described_class.resolves_to_private_ip?(nil)).to be false
      expect(described_class.resolves_to_private_ip?("")).to be false
    end

    it "detects private addresses among resolved results" do
      allow(Resolv).to receive(:getaddresses).with("internal.example.com")
        .and_return(["93.184.216.34", "10.0.0.5"])
      expect(described_class.resolves_to_private_ip?("internal.example.com")).to be true
    end

    it "returns false when all resolved addresses are public" do
      allow(Resolv).to receive(:getaddresses).with("public.example.com")
        .and_return(["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])
      expect(described_class.resolves_to_private_ip?("public.example.com")).to be false
    end

    it "normalizes IPv4-mapped IPv6 addresses before comparison" do
      allow(Resolv).to receive(:getaddresses).with("mapped.example.com")
        .and_return(["::ffff:127.0.0.1"])
      expect(described_class.resolves_to_private_ip?("mapped.example.com")).to be true
    end

    it "ignores unparsable addresses but keeps checking the rest" do
      allow(Resolv).to receive(:getaddresses).with("odd.example.com")
        .and_return(["garbage", "192.168.1.10"])
      expect(described_class.resolves_to_private_ip?("odd.example.com")).to be true
    end
  end

  describe ".private_address?" do
    it "matches loopback, RFC 1918, and link-local ranges" do
      %w[127.0.0.1 10.1.2.3 172.16.0.1 192.168.0.1 169.254.0.1 ::1 fc00::1 fe80::1].each do |addr|
        expect(described_class.private_address?(addr)).to be(true), "expected #{addr} to be private"
      end
    end

    it "does not match public addresses" do
      %w[93.184.216.34 8.8.8.8 2606:4700::1111].each do |addr|
        expect(described_class.private_address?(addr)).to be(false), "expected #{addr} to be public"
      end
    end

    it "returns false for unparsable input" do
      expect(described_class.private_address?("not-an-ip")).to be false
    end
  end
end
