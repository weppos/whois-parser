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
    # = whois.domreg.lt parser
    #
    # Parser for the whois.domreg.lt server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisDomregLt < Base

      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.*)\n/
          ::Regexp.last_match(1).to_sym
        end
      end

      property_supported :available? do
        (status == :available)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Registered:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :nameservers do
        content_for_scanner.scan(/Nameserver:\s+(.+)\n/).flatten.map do |line|
          if line =~ /(.+)\t\[(.+)\]/
            Parser::Nameserver.new(:name => ::Regexp.last_match(1), :ipv4 => ::Regexp.last_match(2))
          else
            Parser::Nameserver.new(:name => line.strip)
          end
        end
      end

    end

  end
end
