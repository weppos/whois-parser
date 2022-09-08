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

    # Parser for the whois.nic.tm server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicTm < Base

      property_not_supported :disclaimer


      property_supported :domain do
        if registered?
          content_for_scanner.match(/^Domain : (.+)\n/)[1]
        elsif available?
          content_for_scanner.match(/^Domain (.+) is available/)[1]
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
        !!(content_for_scanner =~ /^Domain (.+?) is available/)
      end

      property_supported :registered? do
        !available?
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ /Expiry : (.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_not_supported :registrar

      property_supported :registrant_contacts do
        lines = content_for_scanner.scan(/^Owner\s+: (.+)\n/).flatten
        return if lines.empty?

        Parser::Contact.new(
            type:         Parser::Contact::TYPE_REGISTRANT,
            name:         lines[0],
            organization: lines[1],
            address:      lines[2],
            zip:          nil,
            state:        lines[4],
            city:         lines[3],
            country:      lines[5]
        )
      end

      property_not_supported :admin_contacts

      property_not_supported :technical_contacts


      property_supported :nameservers do
        content_for_scanner.scan(/^NS \d\s+: (.+)/).flatten.map do |name|
          Parser::Nameserver.new(name: name)
        end
      end

    end

  end
end
