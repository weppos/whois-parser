#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/verisign'


module Whois
  class Parsers

    class BaseVerisign < Base
      include Scanners::Scannable

      self.scanner = Scanners::Verisign


      property_supported :disclaimer do
        node("Disclaimer")
      end


      property_supported :domain do
        node("Domain Name", &:downcase)
      end

      property_supported :domain_id do
        node("Registry Domain ID")
      end


      property_supported :status do
        # node("Status")
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^No match for/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("Creation Date") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("Updated Date") { |value| parse_time(value) }
      end

      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end


      property_supported :registrar do
        node("Registrar") do |value|
          Parser::Registrar.new(
              id:           last_useful_item(node("Registrar IANA ID")),
              name:         last_useful_item(value),
              url:          referral_url
          )
        end
      end


      property_supported :nameservers do
        Array(node("Name Server")).reject { |value| value =~ /no nameserver/i }.map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end


      def referral_whois
        node("Registrar WHOIS Server")
      end

      def referral_url
        last_useful_item(node("Registrar URL"))
      end


      private

      # In case of "SPAM Response", the response contains more than one item
      # for the same value and the value becomes an Array.
      def last_useful_item(values)
        values.is_a?(Array) ? values.last : values
      end

    end

  end
end
