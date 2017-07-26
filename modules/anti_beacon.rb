require 'public_suffix'

module DNSFilterModule
  class AntiBeacon
    # from iodine
    B32 = 'abcdefghijklmnopqrstuvwxyz012345ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    B64 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789+_'
    B128= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
          "\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA" +
          "\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9" +
          "\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8" +
          "\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7" +
          "\xF8\xF9\xFA\xFB\xFC\xFD"
    def initialize(config, logger)
      @config = config
      @logger = logger
      @querylog = []
      @blocked_names = []
      @base32 = /^[#{B32}]{#{len},}$/
      @base64 = /^[#{B64}]{#{len},}$/
    end
    def process(name, res_class, transaction)
      # process request
      if @blocked_names.select {|x| name.end_with? x}.count > 0
        @logger.info "tried to access blocked domain #{name}"
        raise DNSBlockException.new
      end
      ps = PublicSuffix.parse('name')
      third_level_domain = ps.trd
      #
    end
  end
end
