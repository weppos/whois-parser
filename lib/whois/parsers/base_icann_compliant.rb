#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/base_icann_compliant'


module Whois
  class Parsers

    # Base parser for ICANN Compliant servers.
    #
    # @abstract
    # @see http://www.icann.org/en/resources/registrars/raa/approved-with-specs-27jun13-en.htm#whois
    class BaseIcannCompliant < Base
      include Scanners::Scannable

      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^No Data Found/
      }

      property_supported :disclaimer do
        node("field:disclaimer")
      end


      property_supported :domain do
        node("Domain Name")&.downcase
      end

      property_supported :domain_id do
        node("Registry Domain ID")
      end


      property_supported :status do
        if reserved?
          :reserved
        elsif available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!node('status:available')
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        parse_time(node("Creation Date"))
      end

      property_supported :updated_on do
        parse_time(node("Updated Date"))
      end

      property_supported :expires_on do
        parse_time(node("Registry Expiry Date")) || parse_time(node("Registrar Registration Expiration Date"))
      end


      property_supported :registrar do
        return unless node("Registrar")

        Parser::Registrar.new({
            id:           node("Registrar IANA ID"),
            name:         node("Registrar"),
            url:          node("Registrar URL"),
        })
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


      property_supported :nameservers do
        Array(node("Name Server") || node("Name Servers")).reject(&:empty?).map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end

      def reserved?
        !!node("status:reserved")
      end

      def response_throttled?
        !!node("response:throttled")
      end

      protected

      def build_contact(element, type)
        node("#{element} Name") do
          Parser::Contact.new(
              type:         type,
              id:           node("Registry #{element} ID").presence,
              name:         value_for_property(element, 'Name'),
              organization: contact_organization_attribute(element),
              address:      contact_address_attribute(element),
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

      def contact_organization_attribute(element)
        value_for_property(element, 'Organization')
      end

      def contact_address_attribute(element)
        value_for_property(element, 'Street')
      end


      private

      def value_for_phone_property(element, property)
        node("#{element} #{property}") do |phone|
          ext = node("#{element} #{property} Ext")
          phone += " ext: #{ext}" if ext.present?
          phone
        end
      end

      def value_for_property(element, property)
        node("#{element} #{property}") do |values|
          Array(values).reject(&:empty?).join(', ')
        end
      end

    end

  end
end
