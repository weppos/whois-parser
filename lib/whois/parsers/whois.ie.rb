require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # Parser for .ie domains
    class WhoisIe < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^No match\./
      }

      property_supported :expires_on do
        node("Registry Expiry Date") do |value|
          parse_time(value)
        end
      end

      property_supported :registrar do
        return unless node("Registrar")
        Parser::Registrar.new({
            id:           node("Registrar IANA ID"),
            name:         node("Registrar"),
            organization: node("Registrar"),
            url:          node("Registrar URL"),
        })
      end

    end

  end
end
