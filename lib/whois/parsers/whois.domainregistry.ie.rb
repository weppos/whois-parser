#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.domainregistry.ie.rb'


module Whois
  class Parsers

    # Parser for the whois.domainregistry.ie server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisDomainregistryIe < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisDomainregistryIe


      property_supported :disclaimer do
        node("field:disclaimer")
      end


      property_supported :domain do
        node("domain")
      end

      property_not_supported :domain_id


      property_supported :status do
        case node("ren-status", &:downcase)
        when /^active/
          :registered
        when nil
          if node("status:pending")
            :registered
          else
            :available
          end
        else
          Whois::Parser.bug!(ParserError, "Unknown status `#{node('status')}'.")
        end
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("registration") { |value| parse_time(value) }
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        node("renewal") { |value| parse_time(value) }
      end


      property_not_supported :registrar


      property_supported :registrant_contacts do
        node("descr") do |array|
          Parser::Contact.new(
            :type         => Parser::Contact::TYPE_REGISTRANT,
            :id           => nil,
            :name         => array[0]
          )
        end
      end

      property_supported :admin_contacts do
        build_contact("admin-c", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("tech-c", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        Array(node("nserver")).map do |line|
          name, ipv4 = line.split(/\s+/)
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
      end


      private

      def build_contact(element, type)
        Array(node(element)).map do |id|
          next unless (contact = node("field:#{id}"))

          Parser::Contact.new(
            :type         => type,
            :id           => id,
            :name         => contact["person"]
          )
        end.compact
      end

    end

  end
end
