# Maintainers Guide

This document contains information for project maintainers.

## Publishing

Only maintainers are responsible for publishing new versions of Verikloak to RubyGems.

### Steps to Publish

1. Ensure all tests pass locally and in CI.
2. Update the version number in `lib/verikloak/version.rb`.
3. Build the gem:
   ```bash
   gem build verikloak.gemspec
   ```
4. Push to RubyGems:
   ```bash
   gem push verikloak-<version>.gem
   ```

### Notes
- Only maintainers should perform gem publishing.
- Contributors do not need to perform these steps.
- Security fixes should be prioritized for release.
