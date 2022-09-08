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

    # Parser for the whois.usp.ac.fj server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisUspAcFj < Base

      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.+?)\n/
          case ::Regexp.last_match(1).downcase
          when "active"
            :registered
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^The domain (.+?) was not found!$/)
      end

      property_supported :registered? do
        !available?
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ /Expires:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Domain servers:\n\n((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |line|
            name, ipv4 = line.strip.split(/\s+/)
            Parser::Nameserver.new(name: name.downcase, ipv4: ipv4)
          end
        end
      end

    end

  end
end
