#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.rnids.rs.rb'


module Whois
  class Parsers

    # Parser for the whois.rnids.rs server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisRnidsRs < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisRnidsRs


      property_not_supported :disclaimer


      property_supported :domain do
        node("Domain name") { |str| str.chomp(".") }
      end

      property_not_supported :domain_id


      property_supported :status do
        case node("Domain status", &:downcase)
        when nil
          :available
        when 'active'
          :registered
        when 'locked'
          :registered
        when 'in transfer'
          :registered
        when 'expired'
          :expired
        else
          Whois::Parser.bug!(ParserError, "Unknown status `#{node('Domain status')}'.")
        end
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("Registration date") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("Modification date") { |value| parse_time(value) }
      end

      property_supported :expires_on do
        node("Expiration date") { |value| parse_time(value) }
      end


      property_supported :registrar do
        node("Registrar") do |str|
          Parser::Registrar.new(
            :id           => nil,
            :name         => node("Registrar")
          )
        end
      end


      property_supported :registrant_contacts do
        build_contact("Owner", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Administrative contact", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Technical contact", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        Array(node("DNS")).map do |line|
          name, ipv4 = line.split(/ - ?/).map(&:strip)
          name.chomp!(".")
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
      end


      private

      def build_contact(element, type)
        node(element) do |hash|
          Parser::Contact.new(
            :type         => type,
            :id           => nil,
            :name         => hash[element],
            :organization => nil,
            :address      => hash["Address"],
            :city         => nil,
            :zip          => nil,
            :state        => nil,
            :country      => nil,
            :country_code => nil,
            :phone        => nil,
            :fax          => nil,
            :email        => nil
          )
        end
      end

    end

  end
end
