# frozen_string_literal: true

require "test_helper"

class HTTPTimeoutGlobalTest < Minitest::Test
  cover "HTTP::Timeout::Global*"

  def setup
    super
    @io = fake(wait_readable: true, wait_writable: true)
    @socket = fake(to_io: @io, closed?: false)
    @timeout = HTTP::Timeout::Global.new(global_timeout: 5)
    @timeout.instance_variable_set(:@socket, @socket)
  end

  # -- #connect --

  def test_connect_sets_tcp_nodelay_when_nodelay_is_true
    setsockopt_args = nil
    tcp_socket = fake(
      setsockopt: ->(*args) { setsockopt_args = args }
    )

    socket_class = fake(open: tcp_socket)
    @timeout.connect(socket_class, "example.com", 80, nodelay: true)

    assert_equal [Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1], setsockopt_args
  end

  def test_connect_charges_a_failed_attempts_elapsed_time_so_the_next_attempt_gets_a_reduced_budget
    timeout = HTTP::Timeout::Global.new(global_timeout: 5)
    start   = Time.now
    # 1st connect (fails): reset_timer, log_time-decrement, log_time-reset.
    # 2nd connect (succeeds): reset_timer, log_time-decrement, log_time-reset.
    times = [start, start + 4, start + 4, start + 4, start + 4.2, start + 4.2].each
    failing_socket_class    = fake(open: ->(*) { raise Errno::ECONNREFUSED, "refused" })
    succeeding_socket_class = fake(open: ->(*) { Object.new })

    Time.stub(:now, -> { times.next }) do
      assert_raises(Errno::ECONNREFUSED) { timeout.connect(failing_socket_class, "10.0.0.1", 80) }

      # The failed attempt used 4 of the 5 seconds, leaving 1 second, not a fresh 5.
      assert_in_delta 1, timeout.instance_variable_get(:@time_left), 0.001

      timeout.connect(succeeding_socket_class, "10.0.0.2", 80)
    end

    # If the 2nd attempt had been handed a fresh 5s budget instead of the
    # reduced 1s, this would be ~4.8 (5 - 0.2) instead of ~0.8 (1 - 0.2).
    assert_in_delta 0.8, timeout.instance_variable_get(:@time_left), 0.001
  end

  def test_connect_raises_timeout_error_instead_of_the_original_error_when_charging_exhausts_the_budget
    timeout = HTTP::Timeout::Global.new(global_timeout: 5)
    start   = Time.now
    times   = [start, start + 5.5].each
    failing_socket_class = fake(open: ->(*) { raise Errno::ECONNREFUSED, "refused" })

    Time.stub(:now, -> { times.next }) do
      err = assert_raises(HTTP::TimeoutError) { timeout.connect(failing_socket_class, "10.0.0.1", 80) }

      assert_match(/Timed out after using the allocated 5 seconds/, err.message)
    end
  end

  def test_connect_raises_immediately_when_the_budget_is_already_exhausted
    timeout = HTTP::Timeout::Global.new(global_timeout: 5)
    timeout.instance_variable_set(:@time_left, 0)
    attempted = false
    socket_class = fake(open: ->(*) { attempted = true })

    err = assert_raises(HTTP::TimeoutError) { timeout.connect(socket_class, "10.0.0.1", 80) }

    assert_match(/Timed out after using the allocated 5 seconds/, err.message)
    # A zero (or negative) timeout passed to Timeout.timeout is treated as
    # "unbounded" rather than "expired", so the exhausted budget must be
    # caught before ever attempting to open a socket.
    refute attempted, "should not attempt to open a socket with no budget left"
  end

  # -- #connect_ssl --

  def test_connect_ssl_completes_without_error
    connected = Object.new
    socket = fake(
      to_io:            @io,
      closed?:          false,
      connect_nonblock: ->(*) { connected }
    )
    @timeout.instance_variable_set(:@socket, socket)
    @timeout.connect_ssl
  end

  def test_connect_ssl_when_wait_readable_raised_waits_and_retries
    call_count = 0
    connected = Object.new
    socket = fake(
      to_io:            @io,
      closed?:          false,
      connect_nonblock: proc { |*|
        call_count += 1
        raise IO::EAGAINWaitReadable if call_count == 1

        connected
      }
    )
    @timeout.instance_variable_set(:@socket, socket)
    @timeout.connect_ssl
  end

  def test_connect_ssl_when_wait_writable_raised_waits_and_retries
    call_count = 0
    connected = Object.new
    socket = fake(
      to_io:            @io,
      closed?:          false,
      connect_nonblock: proc { |*|
        call_count += 1
        raise IO::EAGAINWaitWritable if call_count == 1

        connected
      }
    )
    @timeout.instance_variable_set(:@socket, socket)
    @timeout.connect_ssl
  end

  # -- #perform_io (via readpartial) --

  def test_readpartial_when_wait_readable_waits_and_retries
    call_count = 0
    socket = fake(
      to_io:         @io,
      closed?:       false,
      read_nonblock: proc { |*|
        call_count += 1
        call_count == 1 ? :wait_readable : "data"
      }
    )
    @timeout.instance_variable_set(:@socket, socket)

    assert_equal "data", @timeout.readpartial(10)
  end

  def test_write_when_wait_writable_waits_and_retries
    call_count = 0
    socket = fake(
      to_io:          @io,
      closed?:        false,
      write_nonblock: proc { |*|
        call_count += 1
        call_count == 1 ? :wait_writable : 4
      }
    )
    @timeout.instance_variable_set(:@socket, socket)

    assert_equal 4, @timeout.write("data")
  end

  def test_readpartial_when_io_wait_readable_raised_waits_and_retries
    call_count = 0
    socket = fake(
      to_io:         @io,
      closed?:       false,
      read_nonblock: proc { |*|
        call_count += 1
        raise IO::EAGAINWaitReadable if call_count == 1

        "data"
      }
    )
    @timeout.instance_variable_set(:@socket, socket)

    assert_equal "data", @timeout.readpartial(10)
  end

  def test_write_when_io_wait_writable_raised_waits_and_retries
    call_count = 0
    socket = fake(
      to_io:          @io,
      closed?:        false,
      write_nonblock: proc { |*|
        call_count += 1
        raise IO::EAGAINWaitWritable if call_count == 1

        4
      }
    )
    @timeout.instance_variable_set(:@socket, socket)

    assert_equal 4, @timeout.write("data")
  end

  def test_readpartial_when_nil_eof_returns_eof
    socket = fake(
      to_io:         @io,
      closed?:       false,
      read_nonblock: nil
    )
    @timeout.instance_variable_set(:@socket, socket)

    assert_equal :eof, @timeout.readpartial(10)
  end

  def test_readpartial_when_eof_error_raised_returns_eof
    socket = fake(
      to_io:         @io,
      closed?:       false,
      read_nonblock: ->(*) { raise EOFError }
    )
    @timeout.instance_variable_set(:@socket, socket)

    assert_equal :eof, @timeout.readpartial(10)
  end

  # -- with per-operation timeouts --

  def test_readpartial_with_per_op_timeouts_uses_global_time_left_as_effective_timeout
    timeout = HTTP::Timeout::Global.new(global_timeout: 100, read_timeout: 100, write_timeout: 100,
                                        connect_timeout: 100)
    call_count = 0
    socket = fake(
      to_io:         @io,
      closed?:       false,
      read_nonblock: proc { |*|
        call_count += 1
        call_count == 1 ? :wait_readable : "data"
      }
    )
    timeout.instance_variable_set(:@socket, socket)

    assert_equal "data", timeout.readpartial(10)
  end

  def test_readpartial_with_tight_per_op_raises_when_read_timeout_fires
    timeout = HTTP::Timeout::Global.new(global_timeout: 100, read_timeout: 0.01, write_timeout: 0.01,
                                        connect_timeout: 0.01)
    io_nil = fake(wait_readable: nil, wait_writable: true)
    socket = fake(
      to_io:         io_nil,
      closed?:       false,
      read_nonblock: :wait_readable
    )
    timeout.instance_variable_set(:@socket, socket)

    err = assert_raises(HTTP::TimeoutError) { timeout.readpartial(10) }
    assert_match(/Read timed out/, err.message)
  end

  def test_write_with_tight_per_op_raises_when_write_timeout_fires
    timeout = HTTP::Timeout::Global.new(global_timeout: 100, read_timeout: 0.01, write_timeout: 0.01,
                                        connect_timeout: 0.01)
    io_nil = fake(wait_readable: true, wait_writable: nil)
    socket = fake(
      to_io:          io_nil,
      closed?:        false,
      write_nonblock: :wait_writable
    )
    timeout.instance_variable_set(:@socket, socket)

    err = assert_raises(HTTP::TimeoutError) { timeout.write("data") }
    assert_match(/Write timed out/, err.message)
  end

  def test_connect_ssl_with_tight_per_op_uses_connect_timeout_for_wait_readable
    timeout = HTTP::Timeout::Global.new(global_timeout: 100, read_timeout: 0.01, write_timeout: 0.01,
                                        connect_timeout: 0.01)
    io_nil = fake(wait_readable: nil, wait_writable: true)
    socket = fake(
      to_io:            io_nil,
      closed?:          false,
      connect_nonblock: ->(*) { raise IO::EAGAINWaitReadable }
    )
    timeout.instance_variable_set(:@socket, socket)
    assert_raises(HTTP::TimeoutError) { timeout.connect_ssl }
  end

  def test_connect_ssl_with_tight_per_op_uses_connect_timeout_for_wait_writable
    timeout = HTTP::Timeout::Global.new(global_timeout: 100, read_timeout: 0.01, write_timeout: 0.01,
                                        connect_timeout: 0.01)
    io_nil = fake(wait_readable: true, wait_writable: nil)
    socket = fake(
      to_io:            io_nil,
      closed?:          false,
      connect_nonblock: ->(*) { raise IO::EAGAINWaitWritable }
    )
    timeout.instance_variable_set(:@socket, socket)
    assert_raises(HTTP::TimeoutError) { timeout.connect_ssl }
  end
end
