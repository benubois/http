# frozen_string_literal: true

require "ipaddr"
require "socket"

module HTTP
  # Denies requests to hostnames and IP addresses matching configured rules
  #
  # @example
  #   HTTP::Blocklist.new([IPAddr.new("127.0.0.0/8"), "internal.example.com"])
  #   HTTP::Blocklist.new(deny: ->(address) { address.loopback? || address.private? })
  class Blocklist
    # Returns existing Blocklist or creates a new one
    #
    # @example
    #   HTTP::Blocklist.new([IPAddr.new("127.0.0.0/8"), "localhost"])
    #
    # @param [HTTP::Blocklist, Array<IPAddr, String>, String] entries
    # @param [#call, nil] deny predicate called with each resolved address
    # @param [#call, nil] observer receives diagnostic events
    # @return [HTTP::Blocklist]
    # @api public
    def self.new(entries = [], deny: nil, observer: nil)
      return entries if entries.is_a?(Blocklist)

      super
    end

    # Initializes a blocklist from address rules, hostname rules, and a predicate
    #
    # @example
    #   HTTP::Blocklist.new([IPAddr.new("169.254.0.0/16")], deny: ->(ip) { ip.loopback? })
    #
    # @param [Array<IPAddr, String>, String] entries address and hostname rules
    # @param [#call, nil] deny called with each resolved address, truthy blocks it
    # @param [#call, nil] observer called with each diagnostic event
    # @return [HTTP::Blocklist]
    # @api public
    def initialize(entries, deny:, observer:)
      rules = Array(entries) #: Array[IPAddr | String]
      hosts = rules.grep(String) #: Array[String]

      @addresses = rules.grep(IPAddr)
      @hosts     = hosts.map { |entry| ".#{normalize_host(entry)}" }
      @deny      = deny
      @observer  = observer
    end

    # Whether a hostname matches any hostname rule
    #
    # @example
    #   blocklist.blocked_host?("api.example.com")
    #
    # @param [String] host hostname to check
    # @return [Boolean]
    # @api public
    def blocked_host?(host)
      name = ".#{normalize_host(host)}"
      @hosts.any? { |rule| name.end_with?(rule) }
    end

    # Whether an address matches any address rule or is denied by the predicate
    #
    # IPv4-mapped IPv6 addresses are reduced to their native IPv4 form first,
    # so `::ffff:127.0.0.1` cannot slip past a `127.0.0.0/8` rule, and `deny`
    # sees the same normalized address.
    #
    # @example
    #   blocklist.blocked_address?(IPAddr.new("127.0.0.1"))
    #
    # @param [IPAddr] address address to check
    # @return [Boolean]
    # @api public
    def blocked_address?(address)
      ip   = address.native
      deny = @deny

      return true if @addresses.any? { |rule| rule.include?(ip) }
      return false unless deny

      deny.call(ip) ? true : false
    end

    # Resolves a hostname and returns the addresses that are not blocked
    #
    # Hostname rules are checked before resolving, so a blocked name never
    # generates DNS traffic. Blocked addresses are filtered out rather than
    # failing the whole host, because the caller connects only to addresses
    # returned here: a host that also resolves to a permitted address stays
    # reachable, and the blocked one is still never dialed. Rejecting the host
    # outright would take down any site that publishes one bad record beside a
    # working one, which is a misconfiguration far more common than an attack.
    #
    # Every permitted address is returned, not just the first, so the caller can
    # fall back across them the way connecting by hostname would.
    #
    # @example
    #   blocklist.validate!("example.com") # => ["93.184.216.34"]
    #
    # @param [String] host hostname or IP address to resolve
    # @param [Numeric, nil] timeout seconds allowed for the resolution
    # @return [Array<String>] the validated addresses to connect to
    # @raise [HTTP::BlockedHostError] when the host or every address is blocked
    # @raise [HTTP::ConnectTimeoutError] when the resolution runs out of time
    # @api public
    def validate!(host, timeout: nil)
      raise BlockedHostError.new("blocked host: #{host}", host: host) if blocked_host?(host)

      started          = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      addresses        = resolve(host, timeout)
      blocked, allowed = addresses.partition { |address| blocked_address?(IPAddr.new(address)) }

      notify(:resolved, host: host, addresses: addresses, allowed: allowed, blocked: blocked,
                        duration: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)

      raise_all_blocked!(host, addresses, blocked) if allowed.empty?

      allowed
    end

    # Sends a diagnostic event to the observer, if one was configured
    #
    # The observer runs inline on the request path and is not rescued, so an
    # observer that raises fails the request. Keep it cheap and total.
    #
    # @example
    #   blocklist.notify(:connect, host: "example.com", address: "93.184.216.34")
    #
    # @param [Symbol] event the event name
    # @param [Hash] payload data describing the event
    # @return [void]
    # @api private
    def notify(event, **payload)
      observer = @observer
      return unless observer

      observer.call(event, payload)
      nil
    end

    # Warns once that a blocklist cannot be enforced through a proxy
    #
    # @example
    #   blocklist.warn_proxy_incompatible
    #
    # @return [void]
    # @api private
    def warn_proxy_incompatible
      return if @warned

      @warned = true
      warn "HTTP::Blocklist: a blocklist cannot be enforced through a proxy, because the proxy " \
           "resolves the target and makes the connection; the addresses checked here are not " \
           "necessarily the ones reached"
    end

    private

    # Raises when every address a hostname resolved to was blocked
    #
    # @example
    #   raise_all_blocked!("example.com", ["fe80::1"], ["fe80::1"])
    #
    # @param [String] host the hostname that was resolved
    # @param [Array<String>] addresses every address it resolved to
    # @param [Array<String>] blocked the addresses that matched a rule
    # @return [void]
    # @raise [HTTP::BlockedHostError] always
    # @api private
    def raise_all_blocked!(host, addresses, blocked)
      raise BlockedHostError.new(
        "#{host} resolves only to blocked addresses: #{blocked.join(', ')}",
        host: host, addresses: addresses, blocked: blocked
      )
    end

    # Resolves a hostname to the addresses it points at
    #
    # @param [String] host hostname or IP address to resolve
    # @param [Numeric, nil] timeout seconds allowed for the resolution
    # @return [Array<String>] the resolved addresses
    # @raise [HTTP::ConnectTimeoutError] when the resolution runs out of time
    # @api private
    def resolve(host, timeout)
      return Addrinfo.getaddrinfo(host, nil, nil, :STREAM).map(&:ip_address) unless timeout

      resolve_within(host, timeout)
    end

    # Resolves a hostname, giving up once the timeout has passed
    #
    # A resolution that runs out of time surfaces as an `ArgumentError`, so it
    # is translated into the same error a slow connect raises. The timeout is
    # only honored where the platform can resolve asynchronously; elsewhere the
    # resolver ignores it.
    #
    # @param [String] host hostname or IP address to resolve
    # @param [Numeric] timeout seconds allowed for the resolution
    # @return [Array<String>] the resolved addresses
    # @raise [HTTP::ConnectTimeoutError] when the resolution runs out of time
    # @api private
    def resolve_within(host, timeout)
      Addrinfo.getaddrinfo(host, nil, nil, :STREAM, nil, nil, timeout: timeout).map(&:ip_address)
    rescue ArgumentError
      raise ConnectTimeoutError, "Resolving #{host} timed out after #{timeout} seconds"
    end

    # Normalizes a hostname for comparison
    #
    # @param [String] host hostname to normalize
    # @return [String] downcased hostname without a trailing dot
    # @api private
    def normalize_host(host)
      host.downcase.chomp(".")
    end
  end
end
