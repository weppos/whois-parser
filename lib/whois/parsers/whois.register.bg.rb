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

    # Parser for the whois.register.bg server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisRegisterBg < Base

      property_supported :status do
        if content_for_scanner =~ /registration status:\s+(.+?)\n/
          case ::Regexp.last_match(1).downcase
          when "registered"
            :registered
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /Domain name (.+?) does not exist/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /activated on:\s+(.*?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ /expires at:\s+(.*?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /NAME SERVER INFORMATION:\n((.+\n)+)\s+\n/
          ::Regexp.last_match(1).split("\n").map do |line|
            if line =~ /(.+) \((.+)\)/
              Parser::Nameserver.new(:name => ::Regexp.last_match(1), :ipv4 => ::Regexp.last_match(2))
            else
              Parser::Nameserver.new(:name => line.strip)
            end
          end
        end
      end

    end

  end
end
