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

    # Parser for the whois.dk-hostmaster.dk server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    # @author Simone Carletti <weppos@weppos.net>
    # @author Mikkel Kristensen <mikkel@tdx.dk>
    #
    class WhoisDkHostmasterDk < Base

      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.+?)\n/
          case ::Regexp.last_match(1).downcase
          when "active"
            :registered
          when "deactivated"
            :expired
          when "reserved"
            :reserved
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^No entries found for the selected source/)
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

      property_supported :expires_on do
        if content_for_scanner =~ /Expires:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        content_for_scanner.scan(/Hostname:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end


      # Checks whether the response has been throttled.
      #
      # @return [Boolean]
      def response_throttled?
        !!(content_for_scanner =~ /# Too many connections[.]/)
      end

    end

  end
end
