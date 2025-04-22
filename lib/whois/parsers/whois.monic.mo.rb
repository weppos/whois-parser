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

    # Parser for the whois.monic.mo server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisMonicMo < Base

      property_not_supported :disclaimer


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
        !!(content_for_scanner =~ /No match for/)
      end

      property_supported :registered? do
        !available?
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :registrar do
        if content_for_scanner =~ /Registrar:\s+(.+)\n/
          Parser::Registrar.new(name: ::Regexp.last_match(1))
        end
      end

      property_not_supported :registrant_contacts

      property_not_supported :admin_contacts

      property_not_supported :technical_contacts


      property_supported :nameservers do
        content_for_scanner.scan(/Name Server:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name.downcase)
        end
      end

    end

  end
end
