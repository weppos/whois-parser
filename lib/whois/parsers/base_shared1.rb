#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/base_shared1'


module Whois
  class Parsers

    # Shared parser 1.
    #
    # @abstract
    class BaseShared1 < Base
      include Scanners::Scannable

      self.scanner = Scanners::BaseShared1


      property_not_supported :disclaimer


      property_supported :domain do
        node('Domain Name')
      end

      property_not_supported :domain_id


      property_supported :status do
        if respond_to?(:reserved?) && reserved?
          :reserved
        else
          Array(node("Status"))
        end
      end

      property_supported :available? do
        !(respond_to?(:reserved?) && reserved?) && !!node('status:available')
      end

      property_supported :registered? do
        !(respond_to?(:reserved?) && reserved?) && !available?
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :registrar do
        node('Registrar Name') do |name|
          Parser::Registrar.new(
              id:   node('Registrar ID'),
              name: node('Registrar Name')
          )
        end
      end


      property_supported :registrant_contacts do
        build_contact('Registrant', Parser::Contact::TYPE_REGISTRANT)
      end

      property_not_supported :admin_contacts

      property_supported :technical_contacts do
        build_contact('Tech', Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        node('Name Server') do |value|
          ipv4s = node('Name Server IP') || Array.new(value.size)
          value.zip(ipv4s).map do |name, ipv4|
            Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
          end
        end
      end


      private

      def build_contact(element, type)
        node("#{element} Contact ID") do
          Parser::Contact.new(
              :type         => type,
              :id           => node("#{element} Contact ID"),
              :name         => node("#{element} Contact Name"),
              :email        => node("#{element} Contact Email")
          )
        end
      end

    end

  end
end
