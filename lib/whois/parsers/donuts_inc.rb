#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icann_compliant'


module Whois
  class Parsers

    # Parser for the whois.donuts.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class DonutsInc < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Domain not found\./,
        pattern_reserved: /^The registration of this domain is restricted/
      }

    end

  end
end
