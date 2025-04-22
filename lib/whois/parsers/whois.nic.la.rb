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

    # Parser for the whois.nic.la server.
    class WhoisNicLa < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^The queried object does not exist:.+\(?DOMAIN NOT FOUND\)?/,
        pattern_disclaimer: /^This whois service is provided by LANIC/
      }

      private

      def build_contact(element, type)
        node("#{element} Email") do |email|
          Parser::Contact.new(type: type, email: email)
        end
      end

    end

  end
end
