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

    #
    # = whois.nic.cl parser
    #
    # Parser for the whois.nic.cl server.
    #
    class WhoisNicCl < Base

      property_supported :domain do
        content_for_scanner.slice(/Domain name:\s+(.+?)$/, 1)
      end

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^(.+?): no entries found.$/)
      end

      property_supported :registered? do
        !available?
      end

      property_supported :registrant_contacts do
        Parser::Contact.new(type: Parser::Contact::TYPE_REGISTRANT,
          name: content_for_scanner[/Registrant name:\s+(.+?)$/, 1],
          organization: content_for_scanner[/Registrant organisation:\s+(.+?)$/, 1])
      end

      property_supported :registrar do
        Parser::Registrar.new(name: content_for_scanner[/Registrar name:\s+(.+?)$/, 1],
          url: content_for_scanner[/Registrar URL:\s+(.+?)$/, 1])
      end

      property_supported :created_on do
        if content_for_scanner =~ /Creation date:\s+(.*)\n/
          parse_time($1)
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Expiration date:\s+(.*)\n/
          parse_time($1)
        end
      end


      property_supported :nameservers do
        content_for_scanner.scan(/Name server:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end

    end

  end
end
