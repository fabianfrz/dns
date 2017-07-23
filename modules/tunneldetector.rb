require 'public_suffix'

module DNSFilterModule
  class TunnelDetector
    def initialize(config, logger)
      @config = config
      @logger = logger
      @querylog = []
      @timespan = @config['TunnelDetection']['Timespan']
      @threshold = @config['TunnelDetection']['Threshold']
      @blocked_names = []
      start_monitor
    end
    def process(name, res_class, transaction)
      # process request
      @querylog << { time: Time.now, name: name, klass: res_class }
      if @blocked_names.select {|x| name.end_with? x}.count > 0
        @logger.info "tried to access blocked domain #{name}"
        raise DNSBlockException.new
      end
    end
    def start_monitor
      Thread.new do
        loop do
          begin
            now = Time.now
            anomaly_scan(now)
            clean_querylog(now)
            sleep @timespan
          rescue e
            @logger.error e
          end
        end
      end
    end
    def clean_querylog(time)
      ts = 2 * @timespan
      @querylog.reject! { |item| (time -  item[:time]) > ts}
    end
    def anomaly_scan(now)
      domain_list = {}
      @querylog.each do |entry|
        parsed = PublicSuffix.parse(entry[:name])
        tmp = domain_list[parsed.domain] ||= []
        tmp << parsed.trd unless tmp.include? parsed.trd
      end
      domain_list.each do |key, value|
        if value.count > @threshold
          unless @blocked_names.include? key
            @logger.warn "tunnel domain detected: #{key}"
            @blocked_names << key
          end
        end
      end
    end
  end
end
