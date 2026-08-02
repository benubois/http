# frozen_string_literal: true

require "test_helper"

class HTTPBlocklistTest < Minitest::Test
  cover "HTTP::Blocklist*"

  LOOPBACK_V4 = IPAddr.new("127.0.0.0/8")

  DENY_LOOPBACK = lambda(&:loopback?)

  # .new

  def test_new_returns_a_given_blocklist_unchanged
    blocklist = HTTP::Blocklist.new(["localhost"])

    assert_same blocklist, HTTP::Blocklist.new(blocklist)
  end

  def test_new_accepts_entries_that_are_not_arrays
    assert HTTP::Blocklist.new("localhost").blocked_host?("localhost")
    assert HTTP::Blocklist.new(Set["localhost"]).blocked_host?("localhost")
  end

  # #blocked_host?

  def test_blocked_host_matches_the_host_and_its_subdomains
    blocklist = HTTP::Blocklist.new(["example.com"])

    assert blocklist.blocked_host?("example.com")
    assert blocklist.blocked_host?("api.example.com")
    refute blocklist.blocked_host?("notexample.com")
    refute blocklist.blocked_host?("example.org")
  end

  def test_blocked_host_ignores_case_and_a_trailing_dot
    blocklist = HTTP::Blocklist.new(["Example.COM"])

    assert blocklist.blocked_host?("API.example.com.")
  end

  def test_blocked_host_only_considers_string_entries
    blocklist = HTTP::Blocklist.new([IPAddr.new("127.0.0.1"), "127.0.0.2"])

    refute blocklist.blocked_host?("127.0.0.1")
    assert blocklist.blocked_host?("127.0.0.2")
  end

  # #blocked_address?

  def test_blocked_address_matches_addresses_and_ranges
    blocklist = HTTP::Blocklist.new([IPAddr.new("169.254.169.254"), LOOPBACK_V4])

    assert blocklist.blocked_address?(IPAddr.new("169.254.169.254"))
    assert blocklist.blocked_address?(IPAddr.new("127.0.0.1"))
    refute blocklist.blocked_address?(IPAddr.new("93.184.216.34"))
  end

  def test_blocked_address_compares_within_an_address_family
    blocklist = HTTP::Blocklist.new([LOOPBACK_V4, IPAddr.new("::1")])

    assert blocklist.blocked_address?(IPAddr.new("::1"))
    assert blocklist.blocked_address?(IPAddr.new("::ffff:127.0.0.1"))
    refute blocklist.blocked_address?(IPAddr.new("::2"))
  end

  def test_blocked_address_only_considers_ipaddr_entries
    blocklist = HTTP::Blocklist.new(["localhost"])

    refute blocklist.blocked_address?(IPAddr.new("127.0.0.1"))
  end

  def test_blocked_address_consults_deny_and_returns_a_boolean
    blocklist = HTTP::Blocklist.new(deny: DENY_LOOPBACK)

    assert blocklist.blocked_address?(IPAddr.new("127.0.0.1"))
    assert_same false, blocklist.blocked_address?(IPAddr.new("93.184.216.34"))
    assert_same false, HTTP::Blocklist.new([]).blocked_address?(IPAddr.new("127.0.0.1"))
  end

  def test_blocked_address_blocks_when_either_entries_or_deny_match
    entries_only = HTTP::Blocklist.new([LOOPBACK_V4], deny: ->(_address) { false })
    deny_only    = HTTP::Blocklist.new([IPAddr.new("10.0.0.0/8")], deny: DENY_LOOPBACK)

    assert entries_only.blocked_address?(IPAddr.new("127.0.0.1"))
    assert deny_only.blocked_address?(IPAddr.new("127.0.0.1"))
  end

  def test_blocked_address_gives_deny_the_native_form_of_a_mapped_address
    seen = []
    blocklist = HTTP::Blocklist.new(deny: ->(address) { seen << address.to_s and false })

    blocklist.blocked_address?(IPAddr.new("::ffff:127.0.0.1"))

    assert_equal ["127.0.0.1"], seen
  end

  # #validate!

  def test_validate_returns_every_permitted_address
    blocklist = HTTP::Blocklist.new([IPAddr.new("10.0.0.0/8")])
    resolved  = [Addrinfo.ip("93.184.216.34"), Addrinfo.ip("93.184.216.35")]

    assert_equal ["127.0.0.1"], blocklist.validate!("127.0.0.1")

    Addrinfo.stub(:getaddrinfo, resolved) do
      assert_equal ["93.184.216.34", "93.184.216.35"], blocklist.validate!("example.com")
    end
  end

  def test_validate_bounds_the_resolution_with_the_given_timeout
    blocklist = HTTP::Blocklist.new([])
    seen      = []
    resolver  = lambda do |*args, **options|
      seen << [args.length, options]
      [Addrinfo.ip("93.184.216.34")]
    end

    Addrinfo.stub(:getaddrinfo, resolver) do
      blocklist.validate!("example.com")
      blocklist.validate!("example.com", timeout: 5)
    end

    assert_equal [[4, {}], [6, { timeout: 5 }]], seen
  end

  def test_validate_raises_a_connect_timeout_when_the_resolution_runs_out_of_time
    blocklist = HTTP::Blocklist.new([])
    resolver  = ->(*, **) { raise ArgumentError, "NULL pointer given" }

    Addrinfo.stub(:getaddrinfo, resolver) do
      err = assert_raises(HTTP::ConnectTimeoutError) { blocklist.validate!("example.com", timeout: 5) }

      assert_equal "Resolving example.com timed out after 5 seconds", err.message
      assert_raises(ArgumentError) { blocklist.validate!("example.com") }
    end
  end

  def test_validate_raises_for_a_blocked_hostname_without_resolving_it
    blocklist = HTTP::Blocklist.new(["blocked.invalid"])

    err = assert_raises(HTTP::BlockedHostError) { blocklist.validate!("api.blocked.invalid") }
    assert_includes err.message, "api.blocked.invalid"
  end

  # A host that publishes one bad record beside a working one is a
  # misconfiguration, not an attack. Rejecting it outright takes the site down;
  # filtering keeps it reachable and still never dials the blocked address.
  def test_validate_filters_blocked_addresses_but_keeps_the_host_reachable
    blocklist = HTTP::Blocklist.new([LOOPBACK_V4])
    resolved  = [Addrinfo.ip("93.184.216.34"), Addrinfo.ip("127.0.0.1")]

    Addrinfo.stub(:getaddrinfo, resolved) do
      assert_equal ["93.184.216.34"], blocklist.validate!("example.com")
    end
  end

  def test_validate_raises_only_when_every_resolved_address_is_blocked
    blocklist = HTTP::Blocklist.new([LOOPBACK_V4])
    resolved  = [Addrinfo.ip("127.0.0.1"), Addrinfo.ip("127.0.0.2")]

    Addrinfo.stub(:getaddrinfo, resolved) do
      err = assert_raises(HTTP::BlockedHostError) { blocklist.validate!("example.com") }

      assert_equal "example.com resolves only to blocked addresses: 127.0.0.1, 127.0.0.2", err.message
      assert_equal "example.com", err.host
      assert_equal ["127.0.0.1", "127.0.0.2"], err.addresses
      assert_equal ["127.0.0.1", "127.0.0.2"], err.blocked
    end
  end

  # The rejection carries what was resolved, so a caller reporting it does not
  # resolve a second time and risk judging a different answer.
  def test_validate_reports_the_permitted_addresses_alongside_the_blocked_ones
    blocklist = HTTP::Blocklist.new(deny: DENY_LOOPBACK)
    resolved  = [Addrinfo.ip("127.0.0.1")]

    Addrinfo.stub(:getaddrinfo, resolved) do
      err = assert_raises(HTTP::BlockedHostError) { blocklist.validate!("example.com") }

      assert_equal ["127.0.0.1"], err.addresses
      assert_equal ["127.0.0.1"], err.blocked
    end
  end

  def test_validate_reports_the_host_on_a_hostname_rule_rejection
    blocklist = HTTP::Blocklist.new(["blocked.invalid"])

    err = assert_raises(HTTP::BlockedHostError) { blocklist.validate!("api.blocked.invalid") }

    assert_equal "api.blocked.invalid", err.host
    assert_empty err.addresses
    assert_empty err.blocked
  end

  # #observer

  def test_observer_receives_the_resolution_outcome
    events    = []
    blocklist = HTTP::Blocklist.new([LOOPBACK_V4], observer: ->(event, data) { events << [event, data] })
    resolved  = [Addrinfo.ip("93.184.216.34"), Addrinfo.ip("127.0.0.1")]

    Addrinfo.stub(:getaddrinfo, resolved) do
      blocklist.validate!("example.com")
    end

    event, data = events.fetch(0)

    assert_equal :resolved, event
    assert_equal "example.com", data.fetch(:host)
    assert_equal ["93.184.216.34", "127.0.0.1"], data.fetch(:addresses)
    assert_equal ["93.184.216.34"], data.fetch(:allowed)
    assert_equal ["127.0.0.1"], data.fetch(:blocked)
    assert_operator data.fetch(:duration), :>=, 0
    # Bounded above too, or emitting a raw clock reading instead of the elapsed
    # time reads as a plausible duration forever.
    assert_operator data.fetch(:duration), :<, 1
  end

  def test_observer_is_optional
    blocklist = HTTP::Blocklist.new([])

    assert_nil blocklist.notify(:resolved, host: "example.com")
  end

  # Whatever the observer returns stays with the observer, so a diagnostic hook
  # can never become something the caller reads a value out of.
  def test_notify_returns_nil_even_when_the_observer_returns_a_value
    blocklist = HTTP::Blocklist.new([], observer: ->(_event, _data) { :reported })

    assert_nil blocklist.notify(:resolved, host: "example.com")
  end

  def test_validate_raises_when_deny_blocks_a_resolved_address
    blocklist = HTTP::Blocklist.new(deny: DENY_LOOPBACK)

    assert_raises(HTTP::BlockedHostError) { blocklist.validate!("127.0.0.1") }
  end

  def test_validate_does_not_warn_and_raises_a_non_retriable_error
    blocklist = HTTP::Blocklist.new([LOOPBACK_V4])
    err = nil

    warning = capture_warning do
      err = assert_raises(HTTP::BlockedHostError) { blocklist.validate!("127.0.0.1") }
    end

    assert_empty warning
    refute_kind_of HTTP::ConnectionError, err
  end

  # #warn_proxy_incompatible

  def test_warn_proxy_incompatible_warns_once
    blocklist = HTTP::Blocklist.new([LOOPBACK_V4])

    warning = capture_warning do
      blocklist.warn_proxy_incompatible
      blocklist.warn_proxy_incompatible
    end

    assert_includes warning, "proxy"
    assert_equal 1, warning.lines.count
  end
end
