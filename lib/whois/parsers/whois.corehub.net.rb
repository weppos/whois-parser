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

    class WhoisCorehubNet < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^No match for/
      }

      property_not_supported :updated_on

      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Admin", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Tech", Parser::Contact::TYPE_TECHNICAL)
      end

      property_supported :nameservers do
        Array.wrap(node("Name Server")).reject(&:empty?).map do |line|
          server = line.match(/^(?<name>[^ ]+)(?: (?<ipv4>\d{1,3}(?:\.\d{1,3})+))?(?: (?<ipv6>[\da-fA-F:]+))?(?: (?<ipv4>\d{1,3}(?:\.\d{1,3})+))?$/).named_captures
          Parser::Nameserver.new(name: server["name"].strip.downcase, ipv4: server["ipv4"], ipv6: server["ipv6"])
        end
      end

      private

      def build_contact(element, type)
        node("#{element} Name") do
          Parser::Contact.new(
            type:         type,
            id:           node("Registry #{element} ID").presence,
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
