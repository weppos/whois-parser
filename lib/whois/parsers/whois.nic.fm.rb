require_relative 'base_icann_compliant'

module Whois
  class Parsers

    class WhoisNicFm < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /DOMAIN NOT FOUND\n/,
      }

      property_supported :expires_on do
        node("Registry Expiry Date") do |value|
          parse_time(value)
        end
      end
    end
  end
end
