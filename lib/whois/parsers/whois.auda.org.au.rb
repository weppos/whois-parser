#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.auda.org.au.rb'


module Whois
  class Parsers

    # Parser for the whois.auda.org.au server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisAudaOrgAu < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisAudaOrgAu


      property_not_supported :disclaimer


      property_supported :domain do
        node("Domain Name")
      end

      property_supported :domain_id do
        node("Registry Domain ID")
      end

      property_supported :disclaimer do
        node("field:disclaimer")
      end

      # == Values for Status
      #
      # @see http://www.auda.org.au/policies/auda-2002-28/
      # @see http://www.auda.org.au/policies/auda-2006-07/
      #
      property_supported :status do
        Array(node("Status"))
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end

      property_not_supported :created_on

      property_supported :updated_on do
        node("Last Modified") { |value| parse_time(value) }
      end

      property_not_supported :expires_on

      property_supported :registrar do
        node("Registrar Name") do |str|
          Parser::Registrar.new(name: str)
        end
      end

      property_supported :registrant_contacts do
        contact = build_contact("Registrant Contact", Parser::Contact::TYPE_REGISTRANT)
        contact.organization = node("Registrant") if contact
        contact
      end

      property_not_supported :admin_contacts

      property_supported :technical_contacts do
        build_contact("Tech Contact", Parser::Contact::TYPE_TECHNICAL)
      end

      property_supported :nameservers do
        Array(node("Name Server")).map do |name|
          Parser::Nameserver.new(name: name)
        end
      end

      private

      def build_contact(element, type)
        node("#{element} ID") do |str|
          Parser::Contact.new({
            type:         type,
            id:           str,
            name:         node("#{element} Name"),
            organization: nil,
            address:      nil,
            city:         nil,
            zip:          nil,
            state:        nil,
            country:      nil,
            phone:        nil,
            fax:          nil,
            email:        node("#{element} Email"),
          })
        end
      end

    end

  end
end
