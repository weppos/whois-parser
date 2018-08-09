#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icb'


module Whois
  class Parsers

    # Parser for the whois.nic.io server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicIo < BaseIcb
      property_supported :domain do
        if content_for_scanner =~ /Domain Name:\s+(.*)\n/
          $1.downcase
        end
      end

      property_supported :status do
        if content_for_scanner.match(/NOT FOUND/)
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Registry Expiry Date:\s+(.*)\n/
          parse_time($1)
        end
      end

      property_supported :nameservers do
        content_for_scanner.scan(/Name Server:\s+(.*)/).map do |name|
          Parser::Nameserver.new(:name => name[0].strip)
        end
      end

    end
  end
end
