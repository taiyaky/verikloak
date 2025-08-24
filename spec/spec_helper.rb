# frozen_string_literal: true

require "bundler/setup"
require "verikloak"

# Enable WebMock to stub external HTTP requests (discovery, jwks)
require "webmock/rspec"
WebMock.disable_net_connect!(allow_localhost: true)

# Optional: Enable code coverage (Uncomment if needed)
# require "simplecov"
# SimpleCov.start

RSpec.configure do |config|
  # Use the expect syntax
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  # Optional: Run only focused tests with `:focus` metadata
  config.filter_run_when_matching :focus

  # Optional: Print the slowest examples at the end
  config.profile_examples = 5

  # Optional: Randomize test order
  config.order = :random
  Kernel.srand config.seed
end
