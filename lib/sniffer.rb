require 'pcap'
require 'thread'

class MemcacheSniffer
  attr_accessor :metrics, :semaphore

  def initialize(config)
    @source  = config[:nic]
    @port    = config[:port]
    @host    = config[:host]

    @metrics = {}
    @metrics[:calls]   = {}
    @metrics[:objsize] = {}
    @metrics[:reqsec]  = {}
    @metrics[:bytes]    = {}
    @metrics[:total_reqs] = 0
    @metrics[:total_bytes] = 0
    @metrics[:stats]   = { :recv => 0, :drop => 0 }

    @semaphore = Mutex.new
  end

  def start
    cap = Pcap::Capture.open_live(@source, 1500)

    @metrics[:start_time] = Time.new.to_f

    @done    = false

    if @host == ""
      cap.setfilter("port #{@port}")
    else
      cap.setfilter("host #{@host} and port #{@port}")
    end

    cap.loop do |packet|
      @metrics[:stats] = cap.stats

      # parse key name, and size from VALUE responses
      if packet.raw_data =~ /VALUE (\S+) \S+ (\S+)/
        key   = $1
        bytes = $2.to_i

        @semaphore.synchronize do
          @metrics[:total_reqs] += 1
          if @metrics[:calls].has_key?(key)
            @metrics[:calls][key] += 1
            @metrics[:bytes][key] += bytes
          else
            @metrics[:calls][key] = 1
            @metrics[:bytes][key] = bytes
          end

          # objsize may vary over the lifetime of a memcache key
          @metrics[:objsize][key] = bytes
          @metrics[:total_bytes] += bytes.to_i
        end
      end

      break if @done
    end

    cap.close
  end

  def done
    @done = true
  end
end
