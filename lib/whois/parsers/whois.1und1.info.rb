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

    # Parser for the whois.1und1.info server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class Whois1und1Info < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^Domain (.+) is not registered here.\n/,
      }
    end

  end
end
