#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/base_shared3'


module Whois
  class Parsers

    # Shared parser 3.
    #
    # @abstract
    class BaseShared3 < Base
      include Scanners::Scannable

      self.scanner = Scanners::BaseShared3


      property_supported :disclaimer do
        node("field:disclaimer")
      end


      property_supported :domain do
        node("domain name", &:downcase)
      end

      property_not_supported :domain_id


      property_supported :status do
        if respond_to?(:reserved?) && reserved?
          :reserved
        elsif available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !(respond_to?(:reserved?) && reserved?) && !!node("status:available")
      end

      property_supported :registered? do
        !(respond_to?(:reserved?) && reserved?) && !available?
      end


      property_supported :created_on do
        node("created date") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("updated date") { |value| parse_time(value) }
      end

      property_supported :expires_on do
        node("expiration date") { |value| parse_time(value) }
      end


      property_supported :registrar do
        node("registrar") do |raw|
          Parser::Registrar.new(
            name: node("registrar"),
            url:  node("url")
          )
        end
      end

      property_supported :registrant_contacts do
        build_contact("owner", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("admin", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("tech", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        node("nameserver") do |array|
          array.map do |name|
            Parser::Nameserver.new(:name => name)
          end
        end
      end


      private

      def build_contact(element, type)
        node("#{element}-contact") do |raw|
          Parser::Contact.new(
              :type         => type,
              :id           => node("#{element}-contact"),
              :name         => node("#{element}-name"),
              :organization => node("#{element}-organization"),
              :address      => node("#{element}-street"),
              :city         => node("#{element}-city"),
              :zip          => node("#{element}-zip"),
              :state        => nil,
              :country_code => node("#{element}-country"),
              :phone        => node("#{element}-phone"),
              :fax          => node("#{element}-fax"),
              :email        => node("#{element}-email")
          )
        end
      end

    end

  end
end
