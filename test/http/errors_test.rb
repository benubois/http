# frozen_string_literal: true

require "test_helper"

class HTTPStatusErrorTest < Minitest::Test
  cover "HTTP::StatusError*"

  def response
    @response ||= HTTP::Response.new(
      status:  404,
      version: "1.1",
      body:    "Not Found",
      request: HTTP::Request.new(verb: :get, uri: "http://example.com/")
    )
  end

  def error
    @error ||= HTTP::StatusError.new(response)
  end

  def test_response_returns_the_response
    assert_same response, error.response
  end

  def test_message_includes_the_status_code
    assert_equal "Unexpected status code 404", error.message
  end
end

class HTTPBlockedHostErrorTest < Minitest::Test
  cover "HTTP::BlockedHostError*"

  # The detail is optional so the plain `raise BlockedHostError, "message"` form
  # keeps working for anyone constructing one directly.
  def test_detail_defaults_to_empty
    err = HTTP::BlockedHostError.new("blocked host: example.com")

    assert_equal "blocked host: example.com", err.message
    assert_nil err.host
    assert_empty err.addresses
    assert_empty err.blocked
  end

  def test_carries_the_resolution_that_was_judged
    err = HTTP::BlockedHostError.new("nope", host: "example.com", addresses: %w[10.0.0.1 93.184.216.34],
                                             blocked: %w[10.0.0.1])

    assert_equal "example.com", err.host
    assert_equal %w[10.0.0.1 93.184.216.34], err.addresses
    assert_equal %w[10.0.0.1], err.blocked
  end
end
