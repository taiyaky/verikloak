# frozen_string_literal: true

require "verikloak/http"

RSpec.describe Verikloak::HTTP do
  describe ".default_connection" do
    it "returns a Faraday connection with retry middleware and timeouts" do
      conn = described_class.default_connection

      expect(conn).to be_a(Faraday::Connection)
      expect(conn.builder.handlers).to include(Faraday::Retry::Middleware)
      expect(conn.builder.adapter).to eq(Faraday::Adapter::NetHttp)
      expect(conn.options.timeout).to eq(described_class::DEFAULT_TIMEOUT)
      expect(conn.options.open_timeout).to eq(described_class::DEFAULT_OPEN_TIMEOUT)
    end

    it "configures retry middleware with the constant options" do
      fake_conn = instance_double(Faraday::Connection)
      request_options = double("RequestOptions")

      expect(fake_conn).to receive(:request).with(:retry, described_class::RETRY_OPTIONS)
      expect(fake_conn).to receive(:options).twice.and_return(request_options)
      expect(request_options).to receive(:timeout=).with(described_class::DEFAULT_TIMEOUT)
      expect(request_options).to receive(:open_timeout=).with(described_class::DEFAULT_OPEN_TIMEOUT)
      expect(fake_conn).to receive(:adapter).with(Faraday.default_adapter)

      expect(Faraday).to receive(:new).and_yield(fake_conn).and_return(fake_conn)

      expect(described_class.default_connection).to eq(fake_conn)
    end
  end
end
