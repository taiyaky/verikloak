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

  describe "#compile_skip_paths + #skip?" do
    context "with exact paths" do
      before { matcher.send(:compile_skip_paths, ["/health", "/ready"]) }

      it "matches exact paths" do
        expect(matcher.send(:skip?, "/health")).to be true
        expect(matcher.send(:skip?, "/ready")).to be true
      end

      it "does not match sub-paths" do
        expect(matcher.send(:skip?, "/health/deep")).to be false
      end

      it "does not match unrelated paths" do
        expect(matcher.send(:skip?, "/api/users")).to be false
      end
    end

    context "with wildcard (prefix) paths" do
      before { matcher.send(:compile_skip_paths, ["/public/*"]) }

      it "matches the prefix itself" do
        expect(matcher.send(:skip?, "/public")).to be true
      end

      it "matches nested paths" do
        expect(matcher.send(:skip?, "/public/css/style.css")).to be true
      end

      it "does not match unrelated paths" do
        expect(matcher.send(:skip?, "/api")).to be false
      end
    end

    context "with root path" do
      before { matcher.send(:compile_skip_paths, ["/"]) }

      it "matches the root" do
        expect(matcher.send(:skip?, "/")).to be true
      end

      it "does not match non-root paths" do
        expect(matcher.send(:skip?, "/anything")).to be false
      end
    end

    context "with mixed patterns" do
      before { matcher.send(:compile_skip_paths, ["/", "/health", "/assets/*"]) }

      it "matches root" do
        expect(matcher.send(:skip?, "/")).to be true
      end

      it "matches exact" do
        expect(matcher.send(:skip?, "/health")).to be true
      end

      it "matches prefix" do
        expect(matcher.send(:skip?, "/assets/logo.png")).to be true
      end

      it "does not match others" do
        expect(matcher.send(:skip?, "/api")).to be false
      end
    end

    context "with empty or nil entries" do
      it "handles nil input gracefully" do
        matcher.send(:compile_skip_paths, nil)
        expect(matcher.send(:skip?, "/anything")).to be false
      end

      it "skips nil and blank entries" do
        matcher.send(:compile_skip_paths, [nil, "", "  ", "/health"])
        expect(matcher.send(:skip?, "/health")).to be true
        expect(matcher.send(:skip?, "/other")).to be false
      end
    end

    context "with Regexp patterns" do
      before { matcher.send(:compile_skip_paths, [/\A\/api\/v\d+\/public/]) }

      it "matches paths that satisfy the regexp" do
        expect(matcher.send(:skip?, "/api/v1/public/docs")).to be true
        expect(matcher.send(:skip?, "/api/v2/public/info")).to be true
      end

      it "does not match paths outside the regexp" do
        expect(matcher.send(:skip?, "/api/v1/private/data")).to be false
      end
    end

    context "with mixed String and Regexp patterns" do
      before { matcher.send(:compile_skip_paths, ["/up", /\A\/health/]) }

      it "matches exact string paths" do
        expect(matcher.send(:skip?, "/up")).to be true
      end

      it "matches regexp paths" do
        expect(matcher.send(:skip?, "/health/live")).to be true
      end

      it "does not match unrelated paths" do
        expect(matcher.send(:skip?, "/api")).to be false
      end
    end
  end

  describe "#normalize_path" do
    it "adds leading slash if missing" do
      expect(matcher.send(:normalize_path, "foo")).to eq("/foo")
    end

    it "collapses multiple slashes" do
      expect(matcher.send(:normalize_path, "//foo///bar")).to eq("/foo/bar")
    end

    it "removes trailing slash (except root)" do
      expect(matcher.send(:normalize_path, "/foo/")).to eq("/foo")
    end

    it "preserves root as '/'" do
      expect(matcher.send(:normalize_path, "/")).to eq("/")
    end

    it "handles nil" do
      expect(matcher.send(:normalize_path, nil)).to eq("/")
    end
  end
end
