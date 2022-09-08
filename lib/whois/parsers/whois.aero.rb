#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias'


module Whois
  class Parsers

    # Parser for the whois.aero server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisAero < BaseAfilias

      self.scanner = Scanners::BaseAfilias, {
        pattern_reserved: /^Name is restricted from registration\n/,
      }


      property_supported :status do
        if reserved?
          :reserved
        else
          Array.wrap(node("Domain Status"))
        end
      end


      property_supported :updated_on do
        node("Updated On") do |value|
          parse_time(value)
        end
      end

      property_supported :expires_on do
        node("Expires On") do |value|
          parse_time(value)
        end
      end


      # NEWPROPERTY
      def reserved?
        !!node("status:reserved")
      end

    end

  end
end
