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

    class WhoisIlaitCom < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^Domain not found\.\n/
      }

      property_supported :available? do
        !!(content_for_scanner =~ /NOT FOUND/)
      end

      property_supported :created_on do
        node("Creation  Date") { |value| parse_time(value) }
      end

      property_supported :registrar do
        return unless node("Registrar")
        Parser::Registrar.new(
          id:           node("Registrar IANA  ID"),
          name:         node("Registrar"),
          organization: node("Registrar"),
          url:          node("Registrar URL")
        )
      end

      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Admin", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Tech", Parser::Contact::TYPE_TECHNICAL)
      end

      private

      def build_contact(element, type)
        node("#{element} Name") do
          Parser::Contact.new(
            type:         type,
            id:           node("#{element} ID").presence,
            name:         value_for_property(element, 'Name'),
            organization: value_for_property(element, 'Organization'),
            address:      value_for_property(element, 'Street'),
            city:         value_for_property(element, 'City'),
            zip:          value_for_property(element, 'Postal Code'),
            state:        value_for_property(element, 'State/Province'),
            country_code: value_for_property(element, 'Country'),
            phone:        value_for_phone_property(element, 'Phone'),
            fax:          value_for_phone_property(element, 'Fax'),
            email:        value_for_property(element, 'Email')
          )
        end
      end

    end
  end
end
