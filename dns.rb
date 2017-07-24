#!/usr/bin/env ruby
require 'async/dns'
require 'yaml'
require 'logger'

module DNSFilterModule; end
class DNSBlockException < RuntimeError; end
class DNSAnsweredException < RuntimeError; end

Dir['./modules/*.rb'].each do |mod|
  require_relative mod
end

class MyServer < Async::DNS::Server
  def initialize(config)
    super ({listen: y2a_tuple(config['Listen'])})
    @resolver ||= Async::DNS::Resolver.new(y2a_tuple(config['Forwarder']))
    @DNS64Prefix = config['DNS64Prefix'] || '::'
    @modules = []
    @logger = Logger.new(STDOUT)
    DNSFilterModule.constants.map {|m| DNSFilterModule.const_get m }.each do |c|
      begin
        @modules << c.new(config, @logger)
        puts "Module loaded: #{c.name}"
      rescue
        puts "Cannot start module #{c.name}"
      end
    end
  end

  def y2a_tuple(data)
    data.map do |x|
      [
        x['proto'].to_s,
        x['host'],
        x['port']
      ]
    end
  end

  def encode_nat_64(addr)
    a = addr.address
    x1 = a[0..1].unpack('H*')[0]
    x2 = a[2..3].unpack('H*')[0]
    "%s:%s" % [x1, x2]
  end

  def process(name, resource_class, transaction)
    begin
      @modules.each do |mod|
        begin
          mod.process(name, resource_class, transaction)
        rescue DNSBlockException
          raise
        rescue DNSAnsweredException
          return
        rescue
          puts $!
        end
      end
      case resource_class.to_s
      when Resolv::DNS::Resource::IN::A.to_s
        transaction.passthrough!(@resolver)
      when Resolv::DNS::Resource::IN::AAAA.to_s
        begin
          addr = @resolver.addresses_for(name, resource_class)
        rescue
          addr = @resolver.addresses_for(name, Resolv::DNS::Resource::IN::A).map do |address|
            @DNS64Prefix + encode_nat_64(address)
          end
        end
        puts addr
        transaction.respond!(addr.first)
      else
        puts "OTHER"
        puts resource_class
        transaction.fail!(:NXDomain)
      end
    rescue DNSBlockException
      transaction.fail!(:NXDomain)
    end
  end
end
config = YAML.load ( File.read ('config.yml'))
Async::Reactor.run do
  server = MyServer.new(config)
  puts "server is running..."
  server.run
  trap("SIGINT") { exit! }
end
