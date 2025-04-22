#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++

require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # Parser for the whois.rotld.ro server.
    class WhoisRotldRo < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^% No entries found/
      }

      property_supported :created_on do
        parse_time(node("Registered On"))
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        parse_time(node("Expires On"))
      end

      property_supported :registrar do
        return unless node("Registrar")

        Parser::Registrar.new({
            name:         node("Registrar"),
            url:          node("Referral URL"),
        })
      end

      property_supported :nameservers do
        Array(node("Nameserver")).reject(&:empty?).map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end

    end

  end
end
