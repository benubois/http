# frozen_string_literal: true

module HTTP
  # Generic error
  class Error < StandardError; end

  # Generic Connection error
  class ConnectionError < Error; end

  # Types of Connection errors
  class ResponseHeaderError < ConnectionError; end
  # Error raised when reading from a socket fails
  class SocketReadError < ConnectionError; end
  # Error raised when writing to a socket fails
  class SocketWriteError < ConnectionError; end

  # Generic Request error
  class RequestError < Error; end

  # Error raised when host matches a blocked host/ip
  class BlockedHostError < RequestError
    # The hostname that was rejected
    #
    # @example
    #   error.host # => "example.com"
    #
    # @return [String, nil]
    # @api public
    attr_reader :host

    # Every address the hostname resolved to
    #
    # Carried on the error so a caller reporting the rejection does not have to
    # resolve the hostname a second time, which costs another lookup and can
    # return a different answer than the one that was actually judged.
    #
    # @example
    #   error.addresses # => ["93.184.216.34", "fe80::1"]
    #
    # @return [Array<String>]
    # @api public
    attr_reader :addresses

    # The subset of {#addresses} that matched a rule
    #
    # @example
    #   error.blocked # => ["fe80::1"]
    #
    # @return [Array<String>]
    # @api public
    attr_reader :blocked

    # Creates a new BlockedHostError
    #
    # @example
    #   BlockedHostError.new("blocked host: example.com", host: "example.com")
    #
    # @param [String] message the error message
    # @param [String, nil] host the hostname that was rejected
    # @param [Array<String>] addresses every address the hostname resolved to
    # @param [Array<String>] blocked the addresses that matched a rule
    # @return [HTTP::BlockedHostError]
    # @api public
    def initialize(message, host: nil, addresses: [], blocked: [])
      super(message)

      @host      = host
      @addresses = addresses
      @blocked   = blocked
    end
  end

  # Generic Response error
  class ResponseError < Error; end

  # Requested to do something when we're in the wrong state
  class StateError < ResponseError; end

  # When status code indicates an error
  class StatusError < ResponseError
    # The HTTP response that caused the error
    #
    # @example
    #   error.response
    #
    # @return [HTTP::Response]
    # @api public
    attr_reader :response

    # Create a new StatusError from a response
    #
    # @example
    #   HTTP::StatusError.new(response)
    #
    # @param [HTTP::Response] response the response with error status
    # @return [StatusError]
    # @api public
    def initialize(response)
      @response = response

      super("Unexpected status code #{response.code}")
    end
  end

  # Raised when `Response#parse` fails due to any underlying reason (unexpected
  # MIME type, or decoder fails). See `Exception#cause` for the original exception.
  class ParseError < ResponseError; end

  # Requested MimeType adapter not found.
  class UnsupportedMimeTypeError < Error; end

  # Generic Timeout error
  class TimeoutError < Error; end

  # Timeout when first establishing the connection
  class ConnectTimeoutError < TimeoutError; end

  # Header value is of unexpected format (similar to Net::HTTPHeaderSyntaxError)
  class HeaderError < Error; end
end
