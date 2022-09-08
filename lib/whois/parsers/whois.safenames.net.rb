#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icann_compliant'


module Whois
  class Parsers

    # Parser for the whois.safenames.net server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisSafenamesNet < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^No match for "[\w.]+"\.\n/,
      }

      property_supported :created_on do
        node('Created Date') do |value|
          parse_time(value)
        end
      end


      private

      def contact_organization_attribute(element)
        value_for_property(element, 'Organisation')
      end

      def contact_address_attribute(element)
        address = (1..2)
                  .map { |i| node("#{element} Address Line #{i}") }
                  .compact.join("\n").chomp
      end

    end

  end
end
