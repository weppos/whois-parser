#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_shared1'


module Whois
  class Parsers

    # Parser for the whois.registry.om server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisRegistryOm < BaseShared1

      self.scanner = Scanners::BaseShared1, {
          pattern_reserved: /^Restricted\n/,
      }


      property_supported :updated_on do
        node("Last Modified") { |value| parse_time(value) }
      end


      def reserved?
        !!node('status:reserved')
      end

    end

  end
end
