require 'pcap'
require 'thread'

class MemcacheSniffer
  attr_accessor :metrics, :semaphore

  def initialize(config)
    @source  = config[:nic]
    @port    = config[:port]
    @host    = config[:host]

    self.reinit
    @semaphore = Mutex.new
  end

  def reinit
    @metrics = {}
    @metrics[:keys] = {}
    @metrics[:total_reqs] = 0
    @metrics[:total_bytes] = 0
    @metrics[:stats]   = { :recv => 0, :drop => 0 }
    @metrics[:start_time] = Time.new.to_f
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
          @metrics[:total_bytes] += bytes.to_i

          if @metrics[:keys].has_key?(key)
            key_metrics = @metrics[:keys][key]
          else
            # initialize
            key_metrics = {
              :calls => 0,
              :objsize => 0,
              :bytes => 0,
            }
            @metrics[:keys][key] = key_metrics
          end
          key_metrics[:calls] += 1
          key_metrics[:bytes] += bytes
          # objsize may vary over the lifetime of a memcache key
          key_metrics[:objsize] = bytes
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
