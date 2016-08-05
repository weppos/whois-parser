#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias'
require 'whois/scanners/whois.nic.me.rb'


module Whois
  class Parsers

    # Parser for the whois.nic.me server.
    class WhoisNicMe < BaseAfilias

      self.scanner = Scanners::WhoisNicMe

      property_supported :status do
        Array.wrap(node("Domain Status"))
      end


      property_supported :created_on do
        node("Creation Date") do |value|
          parse_time(value)
        end
      end

      property_supported :updated_on do
        node("Updated Date") do |value|
          parse_time(value)
        end
      end

      property_supported :expires_on do
        node("Registry Expiry Date") do |value|
          parse_time(value)
        end
      end

      property_supported :registrar do
        return unless node('Sponsoring Registrar')
        Parser::Registrar.new(
          id:   node('Sponsoring Registrar IANA ID'),
          name: node('Sponsoring Registrar')
        )
      end

      property_supported :nameservers do
        Array.wrap(node("Name Server")).reject(&:empty?).map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end


      private

      def build_contact(element, type)
        node("#{element} ID") do
          Parser::Contact.new(
            type:         type,
            id:           node("#{element} ID"),
            name:         node("#{element} Name"),
            organization: node("#{element} Organization"),
            address:      node("#{element} Street"),
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
