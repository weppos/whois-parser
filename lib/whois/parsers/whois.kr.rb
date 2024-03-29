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

    # Parser for the whois.kr server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisKr < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^Above domain name is not registered to KRNIC/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Registered Date\s+:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Last Updated Date\s+:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Expiration Date\s+:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        content_for_scanner.scan(/^\w+ Name Server\n((?:.+\n)+)\n/).flatten.map do |group|
          Parser::Nameserver.new.tap do |nameserver|
            if group =~ /\s+Host Name\s+:\s+(.+)\n/
              nameserver.name = ::Regexp.last_match(1)
            end
            if group =~ /\s+IP Address\s+:\s+(.+)\n/
              nameserver.ipv4 = ::Regexp.last_match(1)
            end
          end
        end
      end

    end

  end
end
