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

    # Parser for the whois.rrpproxy.net server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisRrpproxyNet < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^No match for "[\w.]+"\.\n/,
      }


      property_not_supported :expires_on

    end

  end
end
