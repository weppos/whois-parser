require_relative 'base_icann_compliant'

module Whois
  class Parsers

    class WhoisNicFm < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /DOMAIN NOT FOUND\n/,
      }
    end
  end
end
