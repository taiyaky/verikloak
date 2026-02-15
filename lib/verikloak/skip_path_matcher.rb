# frozen_string_literal: true

require 'set'

module Verikloak
  # Reusable mixin for skip-path normalization and matching.
  #
  # Include this module and call {#compile_skip_paths} during initialization,
  # then call {#skip?} per-request to check whether the path should bypass processing.
  #
  # Supported patterns:
  # * `'/'`           — matches only the root path
  # * `'/foo'`        — exact-match only (matches `/foo` but **not** `/foo/...`)
  # * `'/foo/*'`      — prefix match (matches `/foo` and any nested path under it)
  # * `Regexp`        — matched against the normalized path via `Regexp#match?`
  module SkipPathMatcher
    private

    # Checks whether the request path matches any compiled skip pattern.
    #
    # @param path [String]
    # @return [Boolean]
    def skip?(path)
      np = normalize_path(path)
      return true if @skip_root && np == '/'
      return true if @skip_exacts.include?(np)
      return true if @skip_prefixes.any? { |prefix| np == prefix || np.start_with?("#{prefix}/") }

      @skip_regexps.any? { |re| re.match?(np) }
    end

    # Normalizes paths for stable comparisons:
    # - ensures leading slash
    # - collapses multiple slashes (e.g. //foo///bar -> /foo/bar)
    # - removes trailing slash except for root
    #
    # @param path [String, nil]
    # @return [String]
    def normalize_path(path)
      s = (path || '').to_s
      s = "/#{s}" unless s.start_with?('/')
      s = s.gsub(%r{/+}, '/')
      s.length > 1 ? s.chomp('/') : s
    end

    # Pre-compiles {skip_paths} into fast lookup structures.
    #
    # * `@skip_root` — whether `'/'` is present
    # * `@skip_exacts` — exact-match set (e.g. `'/health'`)
    # * `@skip_prefixes` — wildcard prefixes for `'/*'` (e.g. `'/public'`)
    # * `@skip_regexps` — Regexp patterns matched via `Regexp#match?`
    #
    # @param paths [Array<String, Regexp>]
    # @return [void]
    def compile_skip_paths(paths)
      @skip_root     = false
      @skip_exacts   = Set.new
      @skip_prefixes = []
      @skip_regexps  = []

      Array(paths).each do |raw|
        next if raw.nil?

        if raw.is_a?(Regexp)
          @skip_regexps << raw
          next
        end

        s = raw.to_s.strip
        next if s.empty?

        if s == '/'
          @skip_root = true
          next
        end

        if s.end_with?('/*')
          prefix = normalize_path(s.chomp('/*'))
          next if prefix == '/' # root is handled by @skip_root

          @skip_prefixes << prefix
        else
          exact = normalize_path(s)
          @skip_exacts << exact
        end
      end

      @skip_prefixes.uniq!
    end
  end
end
