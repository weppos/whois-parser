#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++

require_relative 'base'

module Whois
  class Parsers
    # Parser for whois.nic.club server.
    class WhoisNicClub < Base

      property_not_supported :disclaimer

      property_supported :domain do
        if content_for_scanner =~ /Domain Name:\s+(.+)\n/
          $1.downcase
        end
      end

      property_supported :domain_id do
        if content_for_scanner =~ /Domain ID:\s+(.+)\n/
          $1
        end
      end

      property_supported :status do
        available? ? :available : :registered
      end

      property_supported :available? do
        !!(content_for_scanner.strip =~ /^No Data Found/)
      end

      property_supported :registered? do
        !available?
      end

      property_supported :created_on do
        if content_for_scanner =~ /Creation Date:\s+(.+)\n/
          parse_time $1
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Updated Date:\s+(.+)\n/
          parse_time $1
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Registry Expiry Date:\s+(.+)\n/
          parse_time $1
        end
      end

      property_supported :registrant_contacts do
        build_contact('Registrant', Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact('Admin', Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact('Tech', Parser::Contact::TYPE_TECHNICAL)
      end

      property_supported :nameservers do
        content_for_scanner
          .scan(/Name Server:\s+(.+)\n/)
          .flatten
          .map { |ns| Parser::Nameserver.new(name: ns) }
      end

      def response_throttled?
        !!(content_for_scanner.strip =~ /^Number of allowed queries exceeded./)
      end

      private

      def build_contact(element, type)
        Parser::Contact.new(
          type: type,
          id: contact_field(element, 'ID'),
          name: contact_field(element, 'Name'),
          organization: contact_field(element, 'Organization'),
          address: contact_address(element),
          zip: contact_field(element, 'Postal Code'),
          state: contact_field(element, 'State/Province'),
          city: contact_field(element, 'City'),
          country_code: contact_field(element, 'Country'),
          phone: contact_field(element, 'Phone'),
          fax: contact_field(element, 'Fax'),
          email: contact_field(element, 'Email')
        )
      end

      def contact_field(element, field)
        raw = content_for_scanner.slice(/#{element} #{field}:(.*)\n/, 1).strip
        raw.empty? ? nil : raw
      end

      def contact_address(element)
        content_for_scanner
          .scan(/#{element} Street:(.+)?\n/)
          .flatten
          .compact
          .map(&:strip)
          .join("\n")
      end
    end
  end
end
