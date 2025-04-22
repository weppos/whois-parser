#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.yoursrs.com'


module Whois
  class Parsers

    # Parser for the whois.yoursrs.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisYoursrsCom < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisYoursrsCom


      property_supported :domain do
        node("Domain Name", &:downcase)
      end

      property_not_supported :domain_id


      property_supported :status do
        Array(node("Status"))
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("Created On") do |value|
          parse_time(value)
        end
      end

      property_supported :updated_on do
        node("Last Updated On") do |value|
          parse_time(value)
        end
      end

      property_supported :expires_on do
        node("Expiration Date") do |value|
          parse_time(value)
        end
      end


      property_supported :registrar do
        node("Sponsoring Registrar") do |value|
          Parser::Registrar.new(name: value)
        end
      end


      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("ADMIN", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("TECH", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        Array(node("Name Server")).reject(&:empty?).map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end


      private

      def build_contact(element, type)
        node("#{element} ID") do
          address = (1..3)
                    .map { |i| node("#{element} Street#{i}") }
                    .delete_if { |i| i.nil? || i.empty? }
                    .join("\n")

          Parser::Contact.new(
              type:         type,
              id:           node("#{element} ID"),
              name:         node("#{element} Name"),
              organization: node("#{element} Organization"),
              address:      address,
              city:         node("#{element} City"),
              zip:          node("#{element} Postal Code"),
              state:        node("#{element} State"),
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
