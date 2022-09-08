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

    class BaseIcb < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^NOT FOUND/,
      }


      property_not_supported :disclaimer


      property_supported :expires_on do
        node("Registry Expiry Date") do |value|
          parse_time(value)
        end
      end


      property_supported :registrant_contacts do
        node("Registrant Organization") do
          Parser::Contact.new({
              type:         Parser::Contact::TYPE_REGISTRANT,
              organization: node("Registrant Organization"),
              state:        node("Registrant State/Province"),
              country_code: node("Registrant Country"),
          })
        end
      end

      property_not_supported :admin_contacts

      property_not_supported :technical_contacts

    end

  end
end
