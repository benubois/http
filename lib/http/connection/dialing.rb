# frozen_string_literal: true

module HTTP
  class Connection
    # Establishes the TCP connection for a request
    #
    # Without a blocklist this is a single dial against the hostname, exactly as
    # it has always been. With one, the hostname is resolved up front so every
    # address can be checked, which means the socket is handed an address rather
    # than a name — and that gives up the resolver's own address-by-address
    # fallback. These methods hand it back.
    module Dialing
      private

      # Resolve the candidate addresses to connect to, enforcing the blocklist
      #
      # Without a blocklist this is the hostname, so the socket resolves it and
      # keeps whatever fallback the platform provides. With one, it is every
      # address that passed validation.
      #
      # The resolution is bounded by `resolve_timeout`, the same budget the
      # socket is given when it resolves the hostname itself. Using
      # `connect_timeout` here instead would make enabling a blocklist silently
      # impose a resolution deadline that no other request has, and a budget
      # sized for opening a socket is far too short for a resolver that has to
      # retry an unanswered query.
      #
      # @example
      #   connect_addresses(req, options)
      #
      # @param [HTTP::Request] req
      # @param [HTTP::Options] options
      # @return [Array<String>] host or validated addresses to connect to
      # @raise [HTTP::BlockedHostError] when the request target is blocked
      # @api private
      def connect_addresses(req, options)
        blocklist = options.blocklist
        return [req.socket_host] unless blocklist

        proxied = req.using_proxy?
        blocklist.warn_proxy_incompatible if proxied
        addresses = blocklist.validate!(req.host, timeout: options.timeout_options[:resolve_timeout])

        proxied ? [req.socket_host] : addresses
      end

      # Connect to the first candidate address that accepts the connection
      #
      # A host whose first address is unreachable would fail outright where
      # connecting by hostname succeeds, because the socket never gets to try
      # the rest. Every candidate here has already been validated, so working
      # through them in turn restores that fallback without ever dialing an
      # address the blocklist rejected.
      #
      # @example
      #   connect_any(req, options)
      #
      # @param [HTTP::Request] req
      # @param [HTTP::Options] options
      # @return [void]
      # @raise [HTTP::BlockedHostError] when the request target is blocked
      # @raise [HTTP::TimeoutError, IOError, SocketError, SystemCallError] the last error, when every candidate fails
      # @raise [HTTP::ConnectionError] when the candidate list is unexpectedly empty
      # @api private
      def connect_any(req, options)
        @socket   = options.timeout_class.new(**options.timeout_options)
        addresses = connect_addresses(req, options)
        error     = nil #: Exception?

        addresses.each_index do |index|
          return dial(req, options, addresses, index)
        rescue TimeoutError, IOError, SocketError, SystemCallError => e
          error = e
          close_failed_socket if index < addresses.length - 1
        end

        raise error || ConnectionError.new("no address for #{req.host}")
      end

      # Close a socket whose dial failed so the next candidate starts clean
      #
      # Only called when another candidate follows, because the socket is about
      # to be redialed. After the final failure the error propagates and the
      # caller owns the socket, exactly as it did before fallback existed.
      #
      # @example
      #   close_failed_socket
      #
      # @return [void]
      # @api private
      def close_failed_socket
        @socket.close unless @socket.closed?
      end

      # Dial one candidate address, reporting the attempt either way
      #
      # @example
      #   dial(req, options, ["93.184.216.34"], 0)
      #
      # @param [HTTP::Request] req
      # @param [HTTP::Options] options
      # @param [Array<String>] addresses every candidate address
      # @param [Integer] index position of the candidate to dial
      # @return [void]
      # @raise [HTTP::TimeoutError, IOError, SocketError, SystemCallError] when the dial fails
      # @api private
      def dial(req, options, addresses, index)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        address = addresses.fetch(index)
        error   = nil #: Exception?

        @socket.connect(options.socket_class, address, req.socket_port, nodelay: options.nodelay)
      rescue TimeoutError, IOError, SocketError, SystemCallError => e
        error = e
        raise
      ensure
        report_dial(options, req, address: address, index: index,
                                  total: addresses.length, started: started, error: error)
      end

      # Emit a `:connect` event describing one dial attempt
      #
      # `index` and `total` are what make fallback visible: an attempt at a
      # non-zero index only happens because an earlier address failed, so a
      # caller can tell whether address selection is costing it connections or
      # quietly saving them.
      #
      # @example
      #   report_dial(options, req, address: "93.184.216.34", index: 0, total: 1, started: started, error: nil)
      #
      # @param [HTTP::Options] options
      # @param [HTTP::Request] req
      # @param [String] address the address that was dialed
      # @param [Integer] index position of this candidate
      # @param [Integer] total number of candidates
      # @param [Float] started monotonic clock reading from before the dial
      # @param [Exception, nil] error the failure, or nil when the dial succeeded
      # @return [void]
      # @api private
      def report_dial(options, req, address:, index:, total:, started:, error:)
        options.blocklist&.notify(
          :connect,
          host: req.host, address: address, index: index, total: total, error: error,
          duration: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        )
      end
    end
  end
end
