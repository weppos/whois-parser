require_relative 'base_icann_compliant'

module Whois
  class Parsers

    class WhoisNicGoogle < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /Domain not found.\n/
      }
    end
  end
end
