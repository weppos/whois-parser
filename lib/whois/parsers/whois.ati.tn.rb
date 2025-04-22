#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.ati.tn.rb'


module Whois
  class Parsers

    # Parser for the whois.ati.tn server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisAtiTn < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisAtiTn


      property_supported :disclaimer do
        node("field:disclaimer")
      end


      property_supported :domain do
        node("Domain")
      end

      property_not_supported :domain_id


      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("Acivated") { |value| parse_time(value) }
      end

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :registrar do
        node("Registrar") do |value|
          Parser::Registrar.new(name: value)
        end
      end

      property_supported :registrant_contacts do
        build_contact("Owner", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Admin.", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Tech.", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        Array(node("NameServers")).map do |line|
          name, ipv4 = line.match(/(.+)\. \[(.+)\]/)[1, 2]
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
      end


      private

      def build_contact(element, type)
        node("#{element} Name") do
          Parser::Contact.new(
            type:         type,
            name:         node("#{element} Name"),
            address:      node("#{element} Address"),
            phone:        node("#{element} Tel"),
            fax:          node("#{element} Fax"),
            email:        node("#{element} Email"),
            created_on:   node("#{element} Created") { |value| parse_time(value) },
            updated_on:   node("#{element} Updated") { |value| parse_time(value) }
          )
        end
      end

    end

  end
end
