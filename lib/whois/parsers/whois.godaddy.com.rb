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

    # Parser for the whois.godaddy.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisGodaddyCom < BaseIcannCompliant

      # The server is contacted only in case of a registered domain.
      property_supported :available? do
        false
      end

      property_supported :registered? do
        !available?
      end


      property_supported :updated_on do
        node("Update Date") do |value|
          parse_time(value)
        end
      end

    end

  end
end
