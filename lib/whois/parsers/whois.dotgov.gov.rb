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

    # Parser for the whois.dotgov.gov server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisDotgovGov < Base

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
        !registered?
      end

      property_supported :registered? do
        !!(content_for_scanner =~ /Domain Name:/)
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_not_supported :nameservers

    end

  end
end
