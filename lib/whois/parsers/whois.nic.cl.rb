#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'


module Whois
  class Parsers

    #
    # = whois.nic.cl parser
    #
    # Parser for the whois.nic.cl server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicCl < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^(.+?): no existe$/)
      end

      property_supported :registered? do
        !available?
      end


      property_not_supported :created_on

      # TODO: custom date format with foreign month names
      # property_supported :updated_on do
      #   if content_for_scanner =~ /changed:\s+(.*)\n/
      #     parse_time($1.split(" ", 2).last)
      #   end
      # end

      property_not_supported :expires_on


      property_supported :nameservers do
        if content_for_scanner =~ /Servidores de nombre \(Domain servers\):\n((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |line|
            line.strip!
            line =~ /(.+) \((.+)\)/
            Parser::Nameserver.new(:name => ::Regexp.last_match(1), :ipv4 => ::Regexp.last_match(2))
          end
        end
      end

    end

  end
end
