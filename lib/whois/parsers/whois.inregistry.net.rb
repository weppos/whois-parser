#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias'


module Whois
  class Parsers

    # Parser for the whois.inregistry.net server.
    class WhoisInregistryNet < BaseAfilias

      self.scanner = Scanners::BaseAfilias, {
          # Disclaimer starts with "Access to" in .in servers
          pattern_disclaimer: /^Access to/,
      }

    end

  end
end
