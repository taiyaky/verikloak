# This test file verifies the version number of the Verikloak gem.

# frozen_string_literal: true

require "spec_helper"

RSpec.describe Verikloak do
  # Check that the version number is defined and not nil
  it "has a version number" do
    expect(Verikloak::VERSION).not_to be_nil
  end
end
