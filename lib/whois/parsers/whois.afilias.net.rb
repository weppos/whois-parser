#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias2'


module Whois
  class Parsers

    # Parser for the whois.afilias.net server.
    class WhoisAfiliasNet < BaseAfilias2

      self.scanner = Scanners::BaseAfilias, {
          pattern_disclaimer: /^Access to/,
          pattern_reserved: /^(Name is reserved by afilias\n)|(Reserved by Registry\n)/,
      }


      property_supported :status do
        if reserved?
          :reserved
        else
          super()
        end
      end

      # NEWPROPERTY
      def reserved?
        !!node("status:reserved")
      end

      property_supported :domain_id do
        node("Registry Domain ID")
      end

      property_supported :registrar do
        node("Registrar") do |value|
          Parser::Registrar.new(
              id:   node("Registrar IANA ID"),
              name: node("Registrar"),
              organization: node("Registrar"),
              url:  node("Registrar URL")
          )
        end
      end

      private

      def build_contact(element, type)
        node("Registry #{element} ID") do
          address = ["", "1", "2", "3"].
              map { |i| node("#{element} Street#{i}") }.
              delete_if { |i| i.nil? || i.empty? }.
              join("\n")

          Parser::Contact.new(
              :type         => type,
              :id           => node("Registry #{element} ID"),
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
