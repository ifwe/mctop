require 'pcap'
require 'thread'

class MemcacheSniffer
  attr_accessor :metrics, :semaphore

  def initialize(config)
    @source  = config[:nic]
    @port    = config[:port]
    @host    = config[:host]
    @agg_filter = config[:agg_filter]

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

      accept = false
      aggregate = false
      # parse key name, and size from VALUE responses
      if packet.raw_data =~ /VALUE (\S+) \S+ (\S+)/
        key   = $1
        bytes = $2.to_i

        if @agg_filter
          if key =~ @agg_filter
            if not $1.nil?
              # try to aggregate
              if $1 == key
                # capture group consumed entire key--not aggregated
                key = $1
              else
                aggregate = true
                # signal that aggregation happened
                key = $1 + '*'
              end
            end
            accept = true
          end # else accept remains false
        else
          accept = true
        end
      end

      if accept
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
          # for aggregate keys, objsize is meaningless, so specify -1
          key_metrics[:objsize] = aggregate ? -1 : bytes
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
