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

    # Parser for the whois.in.ua server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisInUa < Base

      property_supported :status do
        if content_for_scanner =~ /status:\s+(.+?)\n/
          case ::Regexp.last_match(1).split("-").first.downcase
          when "ok"
            :registered
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /No records found for object/)
      end

      property_supported :registered? do
        !available?
      end


      property_not_supported :created_on

      property_supported :updated_on do
        if content_for_scanner =~ /changed:\s+(.*)\n/
          time = ::Regexp.last_match(1).split(" ").last
          Time.strptime(time, "%Y%m%d%H%M%S")
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /status:\s+(.*)\n/
          time = ::Regexp.last_match(1).split(" ").last
          Time.strptime(time, "%Y%m%d%H%M%S")
        end
      end


      property_supported :nameservers do
        content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(name: name.strip.downcase)
        end
      end

    end

  end
end
