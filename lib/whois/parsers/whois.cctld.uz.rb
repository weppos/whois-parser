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

    # Parser for the whois.cctld.uz server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisCctldUz < Base

      property_supported :status do
        if content_for_scanner =~ /^Status: (.+?)\n/
          case ::Regexp.last_match(1).downcase
          when "active" then :registered
          when "reserved" then :reserved
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /not found in database/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Creation Date:(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Updated Date:(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Expiration Date:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Domain servers in listed order:\n((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |name|
            Parser::Nameserver.new(:name => name.strip.chomp("."))
          end
        end
      end

    end

  end
end
