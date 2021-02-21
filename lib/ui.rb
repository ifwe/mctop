require 'curses'

include Curses

class UI
  def initialize(config)
    @config = config

    init_screen
    cbreak
    curs_set(0)

    # set keyboard input timeout - sneaky way to manage refresh rate
    Curses.timeout = @config[:refresh_rate]

    if can_change_color?
      start_color
      init_pair(0, COLOR_WHITE, COLOR_BLACK)
      init_pair(1, COLOR_WHITE, COLOR_BLUE)
      init_pair(2, COLOR_WHITE, COLOR_RED)
    end

    @stat_cols    = %w[ calls objsize req/sec %reqs bw(KB/s) %bw]
    @stat_col_width = 10
    @key_col_width  = 0

    @filter_cutoff = 0
    @commands = {
      'Q' => "quit",
      'C' => "sort by calls",
      'S' => "sort by size",
      'B' => "sort by bandwidth",
      'T' => "toggle sort order (asc|desc)"
    }
  end

  def header
    # pad stat columns to @stat_col_width
    @stat_cols = @stat_cols.map { |c| sprintf("%#{@stat_col_width}s", c) }

    # key column width is whatever is left over
    @key_col_width = cols - (@stat_cols.length * @stat_col_width)

    attrset(color_pair(1))
    setpos(0,0)
    addstr(sprintf "%-#{@key_col_width}s%s", "memcache key", @stat_cols.join)
  end

  def footer
    footer_text = @commands.map { |k,v| "#{k}:#{v}" }.join(' | ')
    setpos(lines-1, 0)
    attrset(color_pair(2))
    addstr(sprintf "%-#{cols}s", footer_text)
  end

  def render_stats(sniffer, sort_mode, sort_order = :desc)
    render_start_t = Time.now.to_f * 1000

    # subtract header + footer lines
    maxlines = lines - 4

    # calculate packet loss ratio
    if sniffer.metrics[:stats][:recv] > 0
      loss = sprintf("%5.2f", (sniffer.metrics[:stats][:drop].to_f / sniffer.metrics[:stats][:recv].to_f) * 100)
    else
      loss = 0
    end

    if sniffer.metrics[:start_time].nil? then
      elapsed = nil
      kbps = nil
      rps = nil
    else
      elapsed = Time.now.to_f - sniffer.metrics[:start_time]
      kbps = Float(sniffer.metrics[:total_bytes]) / 1024 / elapsed
      rps = Float(sniffer.metrics[:total_reqs]) / elapsed
    end

    # construct and render footer stats lines
    setpos(lines-3,0)
    attrset(color_pair(2))
    key_count = sniffer.metrics[:keys].keys.count
    header_summary = sprintf "%-28s %-14s %-30s",
      "sort mode: #{sort_mode.to_s} (#{sort_order.to_s})",
      "keys: #{key_count}",
      "packets (recv/dropped): #{sniffer.metrics[:stats][:recv]} / #{sniffer.metrics[:stats][:drop]} (#{loss}%)"
    addstr(sprintf "%-#{cols}s", header_summary)

    setpos(lines-2,0)
    header_summary2 = sprintf(
      "reqs: %10d  KB: %10d  elapsed: %6d  reqs/sec: %8.1f  reqs/key: %8.2f  KB/sec: %8.1f",
      sniffer.metrics[:total_reqs],
      sniffer.metrics[:total_bytes] / 1024,
      elapsed.nil? ? 0 : elapsed,
      rps.nil? ? 0 : rps,
      key_count == 0 ? 0 : Float(sniffer.metrics[:total_reqs]) / key_count,
      kbps.nil? ? 0 : kbps,
    )
    addstr(sprintf "%-#{cols}s", header_summary2)

    # reset colours for main key display
    attrset(color_pair(0))

    subset = []
    total_reqs = 0
    total_bytes = 0

    sniffer.semaphore.synchronize do
      # we may have seen no packets received on the sniffer thread
      return if elapsed.nil?

      total_reqs = sniffer.metrics[:total_reqs]
      total_bytes = sniffer.metrics[:total_bytes]

      if @config[:discard_thresh] > 0
        sniffer.metrics[:keys].each do |key, key_metrics|
            reqsec = key_metrics[:calls] / elapsed

          # if req/sec is <= the discard threshold delete those keys from
          # the metrics hash - this is a hack to manage the size of the
          # metrics hash in high volume environments
          if reqsec <= @config[:discard_thresh]
            sniffer.metrics[:keys].delete(key)
          end
        end
      end

      # In order to reduce the size to be sorted, extract only the values
      # we expect will be displayed.
      subset = []
      if sort_order == :asc
        subset = sniffer.metrics[:keys].select { |_, v| v[sort_mode] <= @filter_cutoff }
      else
        subset = sniffer.metrics[:keys].select { |_, v| v[sort_mode] >= @filter_cutoff }
      end

      # If the filtered set is too small, though, then fall back to the full
      # set. This will happen:
      # * once each time the user changes the sorting
      # * whenever there aren't enough entries in the full set anyway, but who cares?
      if subset.length < maxlines
        subset = sniffer.metrics[:keys].each
      end
    end

    top = subset.sort { |a,b| a[1][sort_mode] <=> b[1][sort_mode] }
    unless sort_order == :asc
      top.reverse!
    end

    last_index = maxlines - 1
    if last_index >= top.length
      last_index = top.length - 1
    end

    if last_index >= 0
      @filter_cutoff = top[last_index][1][sort_mode]
    end

    for i in 0..maxlines-1
      if i < top.length
        key = top[i][0]
        key_metrics = top[i][1]

        # if the key is too wide for the column truncate it and add an ellipsis
        if key.length > @key_col_width
          display_key = key[0..@key_col_width-4]
          display_key = "#{display_key}..."
        else
          display_key = key
        end

        bytes = key_metrics[:bytes]
        # render each key
        line = sprintf "%-#{@key_col_width}s %9.d %9.d %9.2f %9.2f %9.2f %9.2f",
                 display_key,
                 key_metrics[:calls],
                 key_metrics[:objsize],
                 Float(key_metrics[:calls]) / elapsed,
                 100 * Float(key_metrics[:calls]) / total_reqs,
                 Float(bytes) / 1024 / elapsed,
                 100 * Float(bytes) / total_bytes
      else
        # we're not clearing the display between renders so erase past
        # keys with blank lines if there's < maxlines of results
        line = " "*cols
      end

      setpos(1+i, 0)
      addstr(line)
    end

    # print render time in status bar
    runtime = (Time.now.to_f * 1000) - render_start_t
    attrset(color_pair(2))
    setpos(lines-3, cols-18)
    addstr(sprintf "rt: %8.3f (ms)", runtime)
  end

  def input_handler
    # Curses.getch has a bug in 1.8.x causing non-blocking
    # calls to block reimplemented using IO.select
    if RUBY_VERSION =~ /^1.8/
	   refresh_secs = @config[:refresh_rate].to_f / 1000

      if IO.select([STDIN], nil, nil, refresh_secs)
        c = getch
        c.chr
      else
        nil
      end
    else
      getch
    end
  end

  def done
    nocbreak
    close_screen
  end
end
