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

    # Parser for the whois.nic.es server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicEs < Base

      property_supported :domain do
        if content_for_scanner =~ /Domain Name:\s+(.+)\n/
          ::Regexp.last_match(1).downcase
        end
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
        !!(content_for_scanner =~ /There is no information available on the domain consulted/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Creation Date:\s+(.+)\n/
          DateTime.strptime(::Regexp.last_match(1), "%d/%m/%y").to_time
        end
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ /Expiration Date:\s+(.+)\n/
          DateTime.strptime(::Regexp.last_match(1), "%d/%m/%y").to_time
        end
      end


      property_supported :registrar do
        Parser::Registrar.new(name: 'ES-NIC')
      end


      property_supported :registrant_contacts do
        if content_for_scanner =~ /Registrant Name:\s+(.+)\n/
          Parser::Contact.new(
              type:         Parser::Contact::TYPE_REGISTRANT,
              name:         ::Regexp.last_match(1).to_s.strip,
          )
        end
      end

      property_not_supported :admin_contacts

      property_not_supported :technical_contacts


      property_supported :nameservers do
        content_for_scanner.scan(/Name Server \d{1}:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(name: name)
        end
      end

    end

  end
end
