# frozen_string_literal: true

# Main entry point for the Verikloak gem.
# This file requires all core components so that they can be loaded
# by simply requiring 'verikloak'.
require 'verikloak/version'
require 'verikloak/errors'
require 'verikloak/http'
require 'verikloak/discovery'
require 'verikloak/jwks_cache'
require 'verikloak/token_decoder'
require 'verikloak/middleware'
