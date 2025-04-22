#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.cnnic.cn.rb'


module Whois
  class Parsers

    # Parser for the whois.cnnic.cn server.
    class WhoisCnnicCn < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisCnnicCn


      property_not_supported :disclaimer


      property_supported :domain do
        node("Domain Name", &:downcase)
      end

      property_supported :domain_id do
        node("ROID")
      end


      property_supported :status do
        Array node("Domain Status")
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !reserved? && !available?
      end


      property_supported :created_on do
        node("Registration Time") { |value| parse_time(value) }
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        node("Expiration Time") { |value| parse_time(value) }
      end


      property_supported :registrar do
        node("Sponsoring Registrar") do |value|
          Parser::Registrar.new(
            id:   value,
            name: value
          )
        end
      end

      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Administrative", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_not_supported :technical_contacts


      property_supported :nameservers do
        Array(node("Name Server")).map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end


      # NEWPROPERTY
      def reserved?
        !!node("status:reserved")
      end


      private

      def build_contact(element, type)
        node("#{element}") do |value|
          Parser::Contact.new(
            :type         => type,
            :id           => node("#{element} ID"),
            :name         => value,
            :email        => node("#{element} Contact Email")
          )
        end
      end

    end
  end
end
