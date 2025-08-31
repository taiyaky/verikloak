# This test suite verifies the behavior of the Verikloak::TokenDecoder class, ensuring it correctly handles JWT decoding, header validations, signature verification, and claim validations.

# frozen_string_literal: true

require "spec_helper"
require "openssl"
require "jwt"

RSpec.describe Verikloak::TokenDecoder do
  let(:rsa)        { OpenSSL::PKey::RSA.generate(2048) }
  let(:public_jwk) do
    jwk = JWT::JWK.create_from(rsa.public_key).export
    jwk["kid"] = "kid-1"
    jwk
  end
  let(:jwks)       { [public_jwk] }
  let(:issuer)     { "https://issuer.example.com/realms/demo" }
  let(:audience)   { "my-client" }
  let(:now)        { Time.now.to_i }

  def encode(payload_overrides = {}, header_overrides = {})
    payload = {
      iss: issuer,
      aud: audience,
      exp: now + 300,
      nbf: now - 10,
      iat: now
    }.merge(payload_overrides)

    headers = { kid: "kid-1", typ: "JWT", alg: "RS256" }.merge(header_overrides)

    JWT.encode(payload, rsa, "RS256", headers)
  end

  subject(:decoder) do
    described_class.new(jwks: jwks, issuer: issuer, audience: audience, leeway: 30)
  end

  context "success" do
    it "returns claims for a valid RS256 token" do
      token = encode
      claims = decoder.decode!(token)
      expect(claims["aud"]).to eq(audience)
      expect(claims["iss"]).to eq(issuer)
    end
  end

  context "header validations" do
    it "raises unsupported_algorithm when alg != RS256" do
      # Build a payload that would otherwise validate
      payload = { iss: issuer, aud: audience, exp: now + 300, nbf: now - 10, iat: now }

      # Sign with HS256 to ensure the header alg is truly HS256 (not RS256)
      hs256_token = JWT.encode(payload, "secret", "HS256", { kid: "kid-hs", alg: "HS256", typ: "JWT" })

      expect { decoder.decode!(hs256_token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("unsupported_algorithm")
        expect(e.message).to match(/Missing or unsupported algorithm/)
      }
    end

    it "raises invalid_token when kid is missing" do
      token = encode({}, { kid: nil })
      expect { decoder.decode!(token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("invalid_token")
        expect(e.message).to match(/missing 'kid'/i)
      }
    end

    it "raises invalid_token when kid is not found in JWKS" do
      token = encode({}, { kid: "unknown" })
      expect { decoder.decode!(token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("invalid_token")
        expect(e.message).to match(/not found in JWKS/)
      }
    end

    it "raises invalid_token when JWK kty is not RSA" do
      non_rsa = public_jwk.merge("kty" => "EC")
      bad = described_class.new(jwks: [non_rsa], issuer: issuer, audience: audience)
      token = encode
      expect { bad.decode!(token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("invalid_token")
        expect(e.message).to match(/Unsupported key type/)
      }
    end
  end

  context "signature and structure" do
    it "raises invalid_signature for tampered payload" do
      token = encode
      
      header, payload, sig = token.split(".")
      # Decode payload, change a claim, and re-encode to keep base64url valid (avoid ruby-jwt base64 deprecation warnings)
      payload_json = JSON.parse(JWT::Base64.url_decode(payload))
      payload_json["aud"] = "tampered-aud"
      tampered_payload = JWT::Base64.url_encode(payload_json.to_json)
      tampered = [header, tampered_payload, sig].join(".")
      expect { decoder.decode!(tampered) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("invalid_token").or eq("invalid_signature")
      }
    end

    it "raises invalid_token for malformed JWT" do
      expect { decoder.decode!("not-a-jwt") }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("invalid_token")
        expect(e.message).to match(/JWT decode failed|verification failed/i)
      }
    end

    it "raises invalid_token when JWK import fails (missing n/e)" do
      broken = public_jwk.dup
      # Ensure both string and symbol keys are removed to avoid env/version differences
      broken.delete("n"); broken.delete(:n)
      broken.delete("e"); broken.delete(:e)
      bad = described_class.new(jwks: [broken], issuer: issuer, audience: audience)
      token = encode
      expect { bad.decode!(token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("invalid_token")
        expect(e.message).to match(/Failed to import JWK/)
      }
    end
  end

  context "claim validations" do
    it "raises expired_token when exp is in the past" do
      token = encode(exp: now - 120) # exceed leeway to force expiration
      expect { decoder.decode!(token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("expired_token")
        expect(e.message).to match(/expired/i)
      }
    end

    it "raises not_yet_valid when nbf is in the future beyond leeway" do
      token = encode(nbf: now + 120)
      expect { decoder.decode!(token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("not_yet_valid")
        expect(e.message).to match(/not yet valid/i)
      }
    end

    it "accepts slightly future nbf within leeway" do
      token = encode(nbf: now + 10) # leeway < 30
      expect(decoder.decode!(token)).to be_a(Hash)
    end

    it "raises invalid_issuer when iss mismatches" do
      token = encode(iss: "https://evil.example.com/")
      expect { decoder.decode!(token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("invalid_issuer")
      }
    end

    it "raises invalid_audience when aud mismatches" do
      token = encode(aud: "someone-else")
      expect { decoder.decode!(token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("invalid_audience")
      }
    end
  
    it "accepts current iat within leeway" do
      token = encode(iat: now)
      expect(decoder.decode!(token)).to be_a(Hash)
    end

    it "raises invalid_token when iat is in the future beyond leeway" do
      token = encode(iat: now + 31) # leeway is 30
      expect { decoder.decode!(token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("invalid_token")
        expect(e.message).to match(/iat|in the future/i)
      }
    end
  end

  context "verification options (leeway and flags)" do
    it "prefers options[:leeway] over top-level leeway" do
      # Top-level leeway is 30 in subject(:decoder), but we pass options[:leeway] = 5
      opt_decoder = described_class.new(
        jwks: jwks, issuer: issuer, audience: audience, leeway: 30, options: { leeway: 5 }
      )
      token = encode(nbf: now + 6) # 6s in the future: allowed by 30, but should fail with options leeway 5
      expect { opt_decoder.decode!(token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("not_yet_valid")
      }
    end
  
    it "allows future iat when verify_iat is disabled via options" do
      opt_decoder = described_class.new(
        jwks: jwks, issuer: issuer, audience: audience, leeway: 0, options: { verify_iat: false }
      )
      token = encode(iat: now + 120) # far in the future
      expect(opt_decoder.decode!(token)).to be_a(Hash)
    end
  
    it "allows expired token when verify_expiration is disabled via options" do
      opt_decoder = described_class.new(
        jwks: jwks, issuer: issuer, audience: audience, options: { verify_expiration: false }
      )
      token = encode(exp: now - 10)
      expect(opt_decoder.decode!(token)).to be_a(Hash)
    end
  
    it "still enforces RS256 even if algorithms option includes RS256" do
      opt_decoder = described_class.new(
        jwks: jwks, issuer: issuer, audience: audience, options: { algorithms: ["RS256"] }
      )
      token = encode # RS256
      expect(opt_decoder.decode!(token)).to be_a(Hash)
  
      # If someone tries to pass HS256 in algorithms, our header guard (alg != RS256) must still block it.
      payload = { iss: issuer, aud: audience, exp: now + 300, nbf: now - 10, iat: now }
      hs256_token = JWT.encode(payload, "secret", "HS256", { kid: "kid-hs", alg: "HS256", typ: "JWT" })
      expect { opt_decoder.decode!(hs256_token) }.to raise_error(Verikloak::TokenDecoderError) { |e|
        expect(e.code).to eq("unsupported_algorithm")
      }
    end
  end
end