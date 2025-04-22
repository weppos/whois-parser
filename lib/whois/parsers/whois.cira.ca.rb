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

    # Parser for the whois.cira.ca server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisCiraCa < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^Not found: (.+)\n/,
          pattern_reserved: /The domain name requested has usage restrictions applied to it.+\n/,
          pattern_disclaimer: /^(%\n)*% Use of CIRA/
      }

      property_supported :disclaimer do
        node("field:disclaimer").gsub(/%\s/, '') # remove the "% " prefix in the disclaimer
      end
    end

  end
end
