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
    # = whois.nic.st parser
    #
    # Parser for the whois.nic.st server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicSt < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /No entries found for domain/)
      end

      property_supported :registered? do
        !available?
      end

      property_supported :created_on do
        if content_for_scanner =~ /Creation Date:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Updated Date:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Expiration Date:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :nameservers do
        content_for_scanner.scan(/nameserver:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(name: name)
        end
      end

    end

  end
end
