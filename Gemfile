# frozen_string_literal: true

source 'https://rubygems.org'

ruby '3.4.5'

gemspec

group :development, :test do
  gem 'bundler-audit', require: false
  gem 'rspec', '~> 3.12'
  gem 'rspec_junit_formatter'
  gem 'rubocop', require: false
  gem 'rubocop-rspec', require: false
end

group :test do
  gem 'rack-test', '~> 2.1'
  gem 'webmock', '~> 3.26'
end
