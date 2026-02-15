# frozen_string_literal: true

require "spec_helper"
require "verikloak/skip_path_matcher"

RSpec.describe Verikloak::SkipPathMatcher do
  # Create a test harness that includes the module
  let(:matcher) do
    obj = Object.new
    obj.extend(described_class)
    obj
  end

  # Expose private methods for testing
  before do
    described_class.private_instance_methods(false).each do |m|
      described_class.send(:public, m)
    end
  end

  describe "#compile_skip_paths + #skip?" do
    context "with exact paths" do
      before { matcher.compile_skip_paths(["/health", "/ready"]) }

      it "matches exact paths" do
        expect(matcher.skip?("/health")).to be true
        expect(matcher.skip?("/ready")).to be true
      end

      it "does not match sub-paths" do
        expect(matcher.skip?("/health/deep")).to be false
      end

      it "does not match unrelated paths" do
        expect(matcher.skip?("/api/users")).to be false
      end
    end

    context "with wildcard (prefix) paths" do
      before { matcher.compile_skip_paths(["/public/*"]) }

      it "matches the prefix itself" do
        expect(matcher.skip?("/public")).to be true
      end

      it "matches nested paths" do
        expect(matcher.skip?("/public/css/style.css")).to be true
      end

      it "does not match unrelated paths" do
        expect(matcher.skip?("/api")).to be false
      end
    end

    context "with root path" do
      before { matcher.compile_skip_paths(["/"]) }

      it "matches the root" do
        expect(matcher.skip?("/")).to be true
      end

      it "does not match non-root paths" do
        expect(matcher.skip?("/anything")).to be false
      end
    end

    context "with mixed patterns" do
      before { matcher.compile_skip_paths(["/", "/health", "/assets/*"]) }

      it "matches root" do
        expect(matcher.skip?("/")).to be true
      end

      it "matches exact" do
        expect(matcher.skip?("/health")).to be true
      end

      it "matches prefix" do
        expect(matcher.skip?("/assets/logo.png")).to be true
      end

      it "does not match others" do
        expect(matcher.skip?("/api")).to be false
      end
    end

    context "with empty or nil entries" do
      it "handles nil input gracefully" do
        matcher.compile_skip_paths(nil)
        expect(matcher.skip?("/anything")).to be false
      end

      it "skips nil and blank entries" do
        matcher.compile_skip_paths([nil, "", "  ", "/health"])
        expect(matcher.skip?("/health")).to be true
        expect(matcher.skip?("/other")).to be false
      end
    end
  end

  describe "#normalize_path" do
    it "adds leading slash if missing" do
      expect(matcher.normalize_path("foo")).to eq("/foo")
    end

    it "collapses multiple slashes" do
      expect(matcher.normalize_path("//foo///bar")).to eq("/foo/bar")
    end

    it "removes trailing slash (except root)" do
      expect(matcher.normalize_path("/foo/")).to eq("/foo")
    end

    it "preserves root as '/'" do
      expect(matcher.normalize_path("/")).to eq("/")
    end

    it "handles nil" do
      expect(matcher.normalize_path(nil)).to eq("/")
    end
  end
end
