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

    # Parser for the whois.dot.tk server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisDotTk < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /domain name not known/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Domain registered:\s(.+)\n/
          DateTime.strptime(::Regexp.last_match(1), "%m/%d/%Y").to_time
        end
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ /Record will expire on:\s(.+)\n/
          DateTime.strptime(::Regexp.last_match(1), "%m/%d/%Y").to_time
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Domain Nameservers:\n((.+\n)+)\s+\n/
          ::Regexp.last_match(1).split("\n").map do |name|
            Parser::Nameserver.new(name: name.strip.downcase)
          end
        end
      end

    end

  end
end
