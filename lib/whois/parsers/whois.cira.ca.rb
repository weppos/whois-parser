#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
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
        node("Domain name")
      end

      property_not_supported :domain_id


      property_supported :status do
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
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          Whois::Parser.bug!(ParserError, "Unable to parse status.")
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("Creation date") { |str| parse_time(str) }
      end

      property_supported :updated_on do
        node("Updated date") { |str| parse_time(str) }
      end

      property_supported :expires_on do
        node("Expiry date") { |str| parse_time(str) }
      end


      property_supported :registrar do
        node("Registrar") do |hash|
          Parser::Registrar.new(
            id:           hash["Number"],
            name:         hash["Name"],
            organization: hash["Name"]
          )
        end
      end


      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Administrative contact", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Technical contact", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        Array.wrap(node("nserver")).map do |line|
          name, ipv4 = line.split(/\s+/)
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
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
        Array.wrap(node("field:nameservers")).map do |line|
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
                      case ::Regexp.last_match(1)
                      when "2007" then "1"
                      when "2010" then "2"
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

      def build_contact(element, type)
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

    end

  end
end
