module DNSFilterModule
  class NameFilter
    def initialize(config, logger)
      @config = config
      @logger = logger
      @domain_list = @config['Redirect'] || {}
    end
    def process(name, res_class, transaction)
      # process request
      data = @domain_list[name]
      return unless data
      data = data[res_class.to_s.split(':').last]
      if data
        transaction.respond!(data)
        raise DNSAnsweredException.new
      end
    end
  end
end
