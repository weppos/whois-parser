#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.cira.ca.rb'


module Whois
  class Parsers

    # Parser for the whois.cira.ca server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisCiraCa < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisCiraCa


      property_supported :disclaimer do
         node("field:disclaimer")
      end


      property_supported :domain do
        return node("Domain Name") || node("Not found") if version == "3"
        node("Domain name")
      end

      property_not_supported :domain_id


      property_supported :status do
        return status_v3 if version == "3"
        status_v1
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node_name = if version == "3"
          "Creation Date"
        else
          "Creation date"
        end

        node(node_name) { |str| parse_time(str) }
      end

      property_supported :updated_on do
        node_name = if version == "3"
          "Updated Date"
        else
          "Updated date"
        end

        node(node_name) { |str| parse_time(str) }
      end

      property_supported :expires_on do
        node_name = if version == "3"
          "Registry Expiry Date"
        else
          "Expiry date"
        end

        node(node_name) { |str| parse_time(str) }
      end


      property_supported :registrar do
        return registrar_v3 if version == "3"
        registrar_v1
      end


      property_supported :registrant_contacts do
        build_contact(Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact(Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact(Parser::Contact::TYPE_TECHNICAL)
      end

      # Nameservers are listed in the following formats:
      #
      #   ns1.google.com
      #   ns2.google.com
      #
      #   ns1.google.com  216.239.32.10
      #   ns2.google.com  216.239.34.10
      #
      property_supported :nameservers do
        node_name = if version == "3"
          "Name Server"
        else
          "field:nameservers"
        end

        Array.wrap(node(node_name)).map do |line|
          name, ipv4 = line.strip.split(/\s+/)
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
      end

      # Attempts to detect and returns the version.
      #
      # TODO: This is very empiric.
      #       Use the available status in combination with the creation date label.
      #
      # NEWPROPERTY
      def version
        cached_properties_fetch :version do
          version = if content_for_scanner =~ /^% \(c\) (.+?) Canadian Internet Registration Authority/
            year = $1.to_i
            if year >= 2019
              "3"
            elsif year >= 2010
              "2"
            elsif year >= 2007
              "1"
            end
          end
          version || Whois::Parser.bug!(ParserError, "Unable to detect version.")
        end
      end

      # NEWPROPERTY
      def valid?
        cached_properties_fetch(:valid?) do
          !invalid?
        end
      end

      # NEWPROPERTY
      def invalid?
        cached_properties_fetch(:invalid?) do
          status == :invalid
        end
      end


      private

      def status_v1
        if content_for_scanner =~ /Domain status:\s+(.+?)\n/
          case node("Domain status", &:downcase)
          when "registered"
            :registered
          when "redemption"
            :registered
          when "auto-renew grace"
            :registered
          when "to be released"
            :registered
          when "pending delete"
            :registered
          when "available"
            :available
          when "unavailable"
            :invalid
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{$1}'.")
          end
        else
          Whois::Parser.bug!(ParserError, "Unable to parse status.")
        end
      end

      def status_v3
        if node("Not found")
          :available
        else
          :registered
        end
      end

      def registrar_v1
        node("Registrar") do |hash|
          Parser::Registrar.new(
            id:           hash["Number"],
            name:         hash["Name"],
            organization: hash["Name"]
          )
        end
      end

      def registrar_v3
        registrar_information = {
          id:           node("Registrar IANA ID"),
          name:         node("Registrar"),
          organization: node("Registrar"),
        }
        registrar_information.compact!
        return if registrar_information.empty?

        Parser::Registrar.new(
          **registrar_information,
        )
      end

      def build_contact(type)
        return build_contact_v3(type) if version == "3"
        build_contact_v1(type)
      end

      def build_contact_v1(type)
        element = case type
        when Parser::Contact::TYPE_REGISTRANT
          'Registrant'
        when Parser::Contact::TYPE_ADMINISTRATIVE
          'Administrative contact'
        when Parser::Contact::TYPE_TECHNICAL
          'Technical contact'
        else
          Whois::Parser.bug!(ParserError, "Invalid contact type #{type}.")
        end

        node(element) do |hash|
          Parser::Contact.new(
            :type         => type,
            :id           => nil,
            :name         => hash["Name"],
            :organization => nil,
            :address      => hash["Postal address"],
            :city         => nil,
            :zip          => nil,
            :state        => nil,
            :country      => nil,
            :phone        => hash["Phone"],
            :fax          => hash["Fax"],
            :email        => hash["Email"]
          )
        end
      end

      def build_contact_v3(type)
        prefix = case type
        when Parser::Contact::TYPE_REGISTRANT
          'Registrant'
        when Parser::Contact::TYPE_ADMINISTRATIVE
          'Admin'
        when Parser::Contact::TYPE_TECHNICAL
          'Tech'
        else
          Whois::Parser.bug!(ParserError, "Invalid contact type #{type}.")
        end

        contact_information = {
          id:           node("Registry #{prefix} ID"),
          name:         node("#{prefix} Name"),
          organization: node("#{prefix} Organization"),
          address:      node("#{prefix} Street"),
          city:         node("#{prefix} City"),
          zip:          node("#{prefix} Postal Code"),
          state:        node("#{prefix} State/Province"),
          country:      node("#{prefix} Country"),
          country_code: node("#{prefix} Country"),
          phone:        node("#{prefix} Phone"),
          fax:          node("#{prefix} Fax"),
          email:        node("#{prefix} Email"),
        }
        contact_information.compact!
        return if contact_information.empty?

        Parser::Contact.new(
          type: type,
          **contact_information,
        )
      end

    end

  end
end
