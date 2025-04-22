#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.cctld.by.rb'


module Whois
  class Parsers

    # Parser for the whois.cctld.by server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    # @author Aliaksei Kliuchnikau <aliaksei.kliuchnikau@gmail.com>
    class WhoisCctldBy < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisCctldBy


      property_not_supported :disclaimer


      property_supported :domain do
        node("Domain Name", &:downcase)
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
        node("Creation Date") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("Updated Date") { |value| parse_time(value) }
      end

      property_supported :expires_on do
        node("Expiration Date") { |value| parse_time(value) }
      end


      property_supported :registrar do
        node("Registrar") do |registrar|
          Parser::Registrar.new(
            id: registrar,
            name: registrar
          )
        end
      end

      property_not_supported :registrant_contacts

      property_not_supported :admin_contacts

      property_not_supported :technical_contacts


      property_supported :nameservers do
        Array(node("Name Server")).map do |name|
          Parser::Nameserver.new(:name => name.downcase)
        end
      end

    end
  end
end
