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

    # Parser for the whois.nic.xxx server.
    class WhoisNicXxx < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^No Data Found/,
          pattern_reserved: /^Reserved Domain Name\n/, # reserved: a.xxx
      }

    end

  end
end
