#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.centralnic.com.rb'


module Whois
  class Parsers

    # Parser for the whois.centralnic.com server.
    class WhoisCentralnicCom < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisCentralnicCom


      property_supported :disclaimer do
        node("field:disclaimer")
      end


      property_supported :domain do
        node("Domain Name") { |str| str.downcase }
      end

      property_supported :domain_id do
        node("Domain ID")
      end


      property_supported :status do
        # OK, RENEW PERIOD, ...
        Array.wrap(
          node("Status") ||
          node("Domain Status")
        )
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("Created On") { |str| parse_time(str) } ||
        node("Creation Date") { |str| parse_time(str) }
      end

      property_supported :updated_on do
        node("Last Updated On") { |str| parse_time(str) } ||
        node("Updated Date") { |str| parse_time(str) }
      end

      property_supported :expires_on do
        node("Expiration Date") { |str| parse_time(str) } ||
        node("Registry Expiry Date") { |str| parse_time(str) }
      end


      property_supported :registrar do
        node("Sponsoring Registrar ID") do
          Parser::Registrar.new(
              :id           => node("Sponsoring Registrar ID"),
              :name         => nil,
              :organization => node("Sponsoring Registrar Organization"),
              :url          => node("Sponsoring Registrar Website")
          )
        end ||
        node("Sponsoring Registrar IANA ID") do
          Parser::Registrar.new(
              :id           => node("Sponsoring Registrar IANA ID"),
              :name         => node("Sponsoring Registrar"),
              :organization => nil,
              :url          => nil
          )
        end
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
        Array.wrap(node("Name Server")).map do |name|
          Parser::Nameserver.new(:name => name.downcase.chomp("."))
        end
      end


      private

      def build_contact(element, type)
        node("#{element} ID") do
          address = [nil, 1, 2, 3]
                    .map { |i| node("#{element} Street#{i}") }
                    .delete_if { |i| i.nil? || i.empty? }
                    .join("\n")
          address = nil if address.empty?

          Parser::Contact.new(
              :type         => type,
              :id           => node("#{element} ID"),
              :name         => node("#{element} Name"),
              :organization => node("#{element} Organization"),
              :address      => address,
              :city         => node("#{element} City"),
              :zip          => node("#{element} Postal Code"),
              :state        => node("#{element} State/Province"),
              :country_code => node("#{element} Country"),
              :phone        => node("#{element} Phone"),
              :fax          => node("#{element} FAX") || node("#{element} Fax"),
              :email        => node("#{element} Email")
          )
        end
      end

    end

  end
end
