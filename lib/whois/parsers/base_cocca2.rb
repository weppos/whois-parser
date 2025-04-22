#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/base_cocca2.rb'


module Whois
  class Parsers

    # Base parser for CoCCA servers.
    #
    # @abstract
    class BaseCocca2 < Base
      include Scanners::Scannable

      self.scanner = Scanners::BaseCocca2


      property_supported :domain do
        node("Domain Name")
      end

      property_supported :domain_id do
        node("Domain ID")
      end


      # TODO: /pending delete/ => :redemption
      # TODO: /pending purge/  => :redemption
      property_supported :status do
        list = Array(node("Domain Status")).map(&:downcase)
        case
        when list.include?("no object found")
          :available
        when list.include?("ok")
          :registered
        else
          Whois::Parser.bug!(ParserError, "Unknown status `#{list.join(', ')}'.")
        end
      end

      property_supported :available? do
        status == :available
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
        if node("Sponsoring Registrar")
          Parser::Registrar.new(
              id:           node("Sponsoring Registrar IANA ID").presence,
              name:         node("Sponsoring Registrar"),
              url:          node("Sponsoring Registrar URL").presence
          )
        end
      end


      property_supported :nameservers do
        Array(node("Name Server")).map do |name|
          Parser::Nameserver.new(name: name)
        end
      end

    end

  end
end
