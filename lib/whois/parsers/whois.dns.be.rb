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

    # Parser for the whois.dns.be server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisDnsBe < Base

      property_supported :domain do
        content_for_scanner.slice(/Domain:\s+(.+?)\n/, 1)
      end


      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.+?)\n/
          case ::Regexp.last_match(1).downcase
          when "available"
            :available
          when "not available"
            :registered
          when "quarantine"
            :redemption
          when "out of service"
            :redemption
          when "not allowed"
            :invalid
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          Whois::Parser.bug!(ParserError, "Unable to parse status.")
        end
      end

      property_supported :available? do
        !invalid? && (status == :available)
      end

      property_supported :registered? do
        !invalid? && !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Registered:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :registrar do
        if (match = content_for_scanner.match(/Registrar:\s+Name:(.+?)\s*Website:(.+?)\n/))
          name, url = match.to_a[1..2]
          Parser::Registrar.new(name: name.strip, url: url.strip)
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Nameservers:\s((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |line|
            if line.strip =~ /(.+) \((.+)\)/
              Parser::Nameserver.new(:name => ::Regexp.last_match(1), :ipv4 => ::Regexp.last_match(2))
            else
              Parser::Nameserver.new(:name => line.strip)
            end
          end
        end
      end


      # Checks whether the response has been throttled.
      #
      # @return [Boolean]
      def response_throttled?
        !!(content_for_scanner =~ /^% (Excessive querying|Maximum queries per hour reached)/) ||
        response_blocked?
      end

      # Checks whether the server has been blocked.
      #
      # @return [Boolean]
      def response_blocked?
        !!(content_for_scanner =~ /^-3: IP address blocked/)
      end


      # NEWPROPERTY
      def invalid?
        cached_properties_fetch(:invalid?) do
          status == :invalid
        end
      end

    end

  end
end
