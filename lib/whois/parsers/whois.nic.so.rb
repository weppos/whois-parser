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
    #
    # = whois.nic.so parser
    #
    # Parser for the whois.nic.so server.
    #
    #
    class WhoisNicSo < BaseIcannCompliant
      include Scanners::Scannable

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Domain Status: No Object Found$/
      }
    end

  end
end
