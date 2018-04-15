#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++

require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for whois.nic.club server.
    class WhoisNicClub < BaseIcannCompliant
      property_not_supported :disclaimer

      property_supported :available? do
        !!(content_for_scanner.strip =~ /^No Data Found/)
      end

      property_supported :expires_on do
        node('Registry Expiry Date') do |value|
          parse_time(value)
        end
      end

      def response_throttled?
        !!(content_for_scanner.strip =~ /^Number of allowed queries exceeded./)
      end
    end
  end
end
