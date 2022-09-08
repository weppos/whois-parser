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

    # Parser for the whois.donuts.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisDonutsCo < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^Domain not found\./,
      }


      property_supported :expires_on do
        node("Registry Expiry Date") do |value|
          parse_time(value)
        end
      end


      property_supported :registrar do
        return unless node("Registrar")

        Parser::Registrar.new({
            id:           node("Registrar IANA ID"),
            name:         node("Registrar"),
            organization: node("Registrar"),
            url:          node("Registrar URL"),
        })
      end



      #
      # def build_contact(element, type)
      #   if (contact = super)
      #     contact.id = node("#{element} ID")
      #   end
      #   contact
      # end

    end

  end
end
