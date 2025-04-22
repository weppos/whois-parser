#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++

require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # Parser for the whois.centralnic.com server.
    class CentralNic < BaseIcannCompliant
      include Scanners::Scannable

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^The queried object does not exist:.+\(?DOMAIN NOT FOUND\)?/,
        pattern_disclaimer: /^The Whois and RDAP services are provided by CentralNic/
      }

      private

      def build_contact(element, type)
        node("#{element} Email") do |email|
          Parser::Contact.new(
            type:          type,
            id:            node("#{element} ID"),
            name:          node("#{element} Name"),
            organization:  node("#{element} Organization"),
            city:          node("#{element} City"),
            address:       contact_address_attribute(element),
            zip:           node("#{element} Postal Code"),
            state:         node("#{element} State/Province"),
            country_code:  node("#{element} Country"),
            phone:         node("#{element} Phone"),
            fax:           node("#{element} FAX") || node("#{element} Fax"),
            email:         email
          )
        end
      end

    end

  end
end
