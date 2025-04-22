#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_whoisd'


module Whois
  class Parsers

    # Parser for the whois.nic.fo server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicFo < BaseWhoisd

      property_not_supported :registrar

      # whois.nic.fo is using an old whoisd version.
      property_supported :technical_contacts do
        node('tech-c') do |value|
          build_contact(value, Parser::Contact::TYPE_TECHNICAL)
        end
      end


      # whois.nic.fo is using an old whoisd version.
      property_supported :nameservers do
        Array(node('nserver')).map do |line|
          Parser::Nameserver.new(:name => line.strip)
        end
      end

    end

  end
end
