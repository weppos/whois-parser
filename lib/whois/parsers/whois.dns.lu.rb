#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'


module Whois
  class Parsers

    # Parser for the whois.dns.lu server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisDnsLu < Base

      property_supported :status do
        if content_for_scanner =~ /domaintype:\s+(.+)\n/
          case ::Regexp.last_match(1).downcase
          when "active"
            :registered
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /% No such domain/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /registered:\s+(.*)\n/
          # Force the parser to use the dd/mm/yyyy format.
          Time.utc(*::Regexp.last_match(1).split("/").reverse)
        end
      end

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :registrar do
        if name = value_for_key('registrar-name')
          Parser::Registrar.new(
              name:         name,
              url:          value_for_key('registrar-url')
          )
        end
      end

      property_supported :registrant_contacts do
        build_contact('org', Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact('adm', Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact('tec', Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        values_for_key('nserver').map do |line|
          if line =~ /(.+) \[(.+)\]/
            Parser::Nameserver.new(name: ::Regexp.last_match(1), ipv4: ::Regexp.last_match(2))
          else
            Parser::Nameserver.new(name: line)
          end
        end
      end


      private

      def build_contact(element, type)
        return unless (name = value_for_key(format("%s-name", element)))

        Parser::Contact.new(
            type:         type,
            id:           nil,
            name:         name,
            address:      value_for_key(format("%s-address", element)),
            city:         value_for_key(format("%s-city", element)),
            zip:          value_for_key(format("%s-zipcode", element)),
            country_code: value_for_key(format("%s-country", element)),
            email:        value_for_key(format("%s-email", element))
        )
      end

      def value_for_key(key)
        values = values_for_key(key)
        if values.size > 1
          values.join(', ')
        else
          values.first
        end
      end

      def values_for_key(key)
        content_for_scanner.scan(/#{key}:\s+(.+)\n/).flatten
      end

    end
  end
end
