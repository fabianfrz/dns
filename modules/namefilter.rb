module DNSFilterModule
  class NameFilter
    def initialize(config, logger)
      @config = config
      @logger = logger
      @domain_list = File.read(config['DomainBlacklist']).lines.select do |line|
        line.length > 4 && line[0] != '#'
      end.map do |line|
        line.gsub(/(\r|\n|\r\n)/,'')
      end
    end
    def process(name, res_class, transaction)
      # process request
      if @domain_list.include? name
        @logger.info "blocked #{name}"
        raise DNSBlockException.new
      end
    end
  end
end
