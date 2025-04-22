#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.denic.de.rb'


module Whois
  class Parsers

    # Parser for the whois.denic.de server.
    #
    # @author Simone Carletti <weppos@weppos.net>
    # @author Aaron Mueller <mail@aaron-mueller.de>
    #
    class WhoisDenicDe < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisDenicDe


      property_supported :disclaimer do
        node("Disclaimer")
      end


      property_supported :domain do
        node("Domain")
      end

      property_not_supported :domain_id


      property_supported :status do
        case node("Status")
        when "connect"
          :registered
        when "free"
          :available
        when "invalid"
          :invalid
        # NEWSTATUS inactive
        # The domain is registered, but there is not DNS entry for it.
        when "failed"
          :registered
        else
          if response_error?
            # NEWSTATUS invalid
            :invalid
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{node('Status')}'.")
          end
        end
      end

      property_supported :available? do
        !invalid? && node("Status") == "free"
      end

      property_supported :registered? do
        !invalid? && !available?
      end


      property_not_supported :created_on

      property_supported :updated_on do
        node("Changed") { |value| parse_time(value) }
      end

      property_not_supported :expires_on


      property_supported :registrar do
        node("Zone-C") do |raw|
          Parser::Registrar.new(name: raw["name"])
        end
      end

      property_supported :registrant_contacts do
        build_contact("Holder", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Admin-C", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Tech-C", Parser::Contact::TYPE_TECHNICAL)
      end


      # Nameservers are listed in the following formats:
      #
      #   Nserver:     ns1.prodns.de. 213.160.64.75
      #   Nserver:     ns1.prodns.de.
      #
      property_supported :nameservers do
        node("Nserver") do |values|
          values.map do |line|
            name, ipv4 = line.split(/\s+/)
            Parser::Nameserver.new(name: name, ipv4: ipv4)
          end
        end
      end


      # Checks whether the response has been throttled.
      #
      # @return [Boolean]
      #
      # @example
      #   % Error: 55000000002 Connection refused; access control limit reached.
      #
      def response_throttled?
        !!node("response:throttled")
      end

      def response_error?
        !!node("response:error")
      end


      def version
        cached_properties_fetch :version do
          if content_for_scanner =~ /^% Version: (.+)$/
            ::Regexp.last_match(1)
          end
        end
      end

      # NEWPROPERTY invalid?
      def invalid?
        cached_properties_fetch :invalid? do
          node("Status") == "invalid" ||
          response_error?
        end
      end


      private

      def build_contact(element, type)
        node(element) do |raw|
          Parser::Contact.new(raw) do |c|
            c.type = type
          end
        end
      end

    end
  end
end
