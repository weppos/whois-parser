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
    # = whois.nic.sm parser
    #
    # Parser for the whois.nic.sm server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicSm < Base

      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.+?)\n/
          case ::Regexp.last_match(1).downcase
          when "active" then :registered
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        (content_for_scanner.strip == "No entries found.")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Registration date: (.+)\n/
          Time.utc(*::Regexp.last_match(1).split('/').reverse)
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Last Update: (.+)\n/
          Time.utc(*::Regexp.last_match(1).split('/').reverse)
        end
      end

      property_not_supported :expires_on


      property_supported :nameservers do
        if content_for_scanner =~ /DNS Servers:\n((.*\n)+)(?:\n|\z)/
          ::Regexp.last_match(1).split("\n").map do |name|
            Parser::Nameserver.new(:name => name.strip)
          end
        end
      end

    end

  end
end
