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
    # = whois.twnic.net.tw
    #
    # Parser for the whois.twnic.net.tw server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisTwnicNetTw < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner.strip == "No Found")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Record created on ([^ ]+) .+\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ /Record expires on ([^ ]+) .+\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Domain servers in listed order:\n((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |name|
            Parser::Nameserver.new(:name => name.strip)
          end
        end
      end

    end

  end
end
