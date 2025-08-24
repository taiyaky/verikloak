# frozen_string_literal: true

require_relative 'lib/verikloak/version'

Gem::Specification.new do |spec|
  spec.name          = 'verikloak'
  spec.version       = Verikloak::VERSION
  spec.authors       = ['taiyaky']

  spec.summary       = 'Rack middleware for verifying Keycloak JWTs via OpenID Connect'
  spec.description   = <<~DESC
    Verikloak is a lightweight Ruby gem that provides JWT access token verification middleware
    for Rack-based applications, including Rails API mode. It uses OpenID Connect discovery
    and JWKS to securely validate tokens issued by Keycloak.
  DESC
  spec.homepage      = 'https://github.com/taiyaky/verikloak'
  spec.license       = 'MIT'

  spec.files         = Dir['lib/**/*.rb'] + %w[README.md LICENSE CHANGELOG.md]
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 3.0'

  # Runtime dependencies
  spec.add_dependency 'faraday', '>= 2.0', '< 3.0'
  spec.add_dependency 'json', '~> 2.6'
  spec.add_dependency 'jwt', '~> 2.7'

  # Metadata for RubyGems
  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['changelog_uri']   = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata['bug_tracker_uri'] = "#{spec.homepage}/issues"
  spec.metadata['documentation_uri'] = "https://rubydoc.info/gems/verikloak/#{Verikloak::VERSION}"
  spec.metadata['rubygems_mfa_required'] = 'true'
end
