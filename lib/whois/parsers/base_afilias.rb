#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icann_compliant'
require 'whois/scanners/base_afilias'


module Whois
  class Parsers

    # Base parser for Afilias servers.
    #
    # @abstract
    class BaseAfilias < BaseIcannCompliant

      self.scanner = Scanners::BaseAfilias


      property_supported :status do
        Array(node("Domain Status"))
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
        Array(node("Name Server")).reject(&:empty?).map do |name|
          Parser::Nameserver.new(:name => name.downcase)
        end
      end

      # Checks whether the response has been throttled.
      #
      # @return [Boolean]
      #
      # @example
      #   WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS
      #
      def response_throttled?
        !!node("response:throttled")
      end

      private

      def build_contact(element, type)
        node("#{element} Organization") do
          address = ["", "1", "2", "3"].
            map { |i| node("#{element} Street#{i}") }.
            delete_if { |i| i.nil? || i.empty? }.
            join("\n").presence
          Parser::Contact.new(
            type:         type,
            id:           node("Registry #{element} ID"),
            name:         node("#{element} Name"),
            organization: node("#{element} Organization"),
            address:      address,
            city:         node("#{element} City"),
            zip:          node("#{element} Postal Code"),
            state:        node("#{element} State/Province"),
            country_code: node("#{element} Country"),
            phone:        node("#{element} Phone"),
            fax:          node("#{element} Fax"),
            email:        node("#{element} Email")
          )
        end
      end

    end

  end
end
