require 'optparse'
require 'pcap'

class CmdLine
  def self.parse(args)
    @config = {}

    opts = OptionParser.new do |opt|
      @config[:agg_filter] = nil
      opt.on '-a', '--agg-filter=REGEX', 'Regex to filter keys; aggregates on first capture group' do |filter|
        @config[:agg_filter] = Regexp.new(filter)
      end

      opt.on('-i', '--interface=NIC', 'Network interface to sniff (required)') do |nic|
        @config[:nic] = nic
      end

      @config[:host] = ''
      opt.on('--host=HOST', 'Network host to sniff on (default all)') do |host|
        @config[:host] = host
      end

      @config[:port] = 11211
      opt.on('-p', '--port=PORT', 'Network port to sniff on (default 11211)') do |port|
        @config[:port] = port
      end

      @config[:discard_thresh] = 0
      opt.on '-d', '--discard=THRESH', Float, 'Discard keys with request/sec rate below THRESH' do |discard_thresh|
        @config[:discard_thresh] = discard_thresh
      end

      @config[:refresh_rate] = 500
      opt.on '-r', '--refresh=MS', Float, 'Refresh the stats display every MS milliseconds' do |refresh_rate|
        @config[:refresh_rate] = refresh_rate
      end

      @config[:refresh_stats] = false
      opt.on '-s', '--[no-]refresh-stats', 'Refresh (clear) stats on display refresh' do |refresh_stats|
        @config[:refresh_stats] = refresh_stats
      end

      @config[:sniff_time] = 500
      opt.on '--sniff-time=MS', Float, 'Allow the sniffer a minimum of this many millesconds each loop' do |sniff_time|
        @config[:sniff_time] = sniff_time
      end

      opt.on_tail '-h', '--help', 'Show usage info' do
        puts opts
        exit
      end
    end

    opts.parse!

    # bail if we're not root
    unless Process::Sys.getuid == 0
      puts "** ERROR: needs to run as root to capture packets"
      exit 1
    end

    # we need need a nic to listen on
    unless @config.has_key?(:nic)
      puts "** ERROR: You must specify a network interface to listen on"
      puts opts
      exit 1
    end

    # we can't do 'any' interface just yet due to weirdness with ruby pcap libs
    if @config[:nic] =~ /any/i
      puts "** ERROR: can't bind to any interface due to odd issues with ruby-pcap"
      puts opts
      exit 1
    end

    @config
  end
end
