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

    # Parser for the whois.nic.hu server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicHu < Base

      property_not_supported :disclaimer


      property_supported :domain do
        if content_for_scanner =~ /domain:\s+(.+)\n/
          ::Regexp.last_match(1)
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
        !!(content_for_scanner =~ %r{/ No match})
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /record created:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_not_supported :registrar


      property_not_supported :registrant_contacts

      property_not_supported :admin_contacts

      property_not_supported :technical_contacts


      property_not_supported :nameservers

    end

  end
end
