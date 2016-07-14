#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icann_compliant'


module Whois
  class Parsers

    # Parser for the whois.domain.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisDomainCom < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^No match for/
      }
      
      property_supported :registrar do
        return unless node('Sponsoring Registrar')
        Parser::Registrar.new(
            id:           node('Sponsoring Registrar IANA ID'),
            name:         node('Sponsoring Registrar'),
            organization: node('Sponsoring Registrar'),
            url:          node('Registrar URL')
        )
      end
    end

  end
end
