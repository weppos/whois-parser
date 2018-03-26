#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icb'


module Whois
  class Parsers

    # Parser for the whois.nic.tm server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicTm < BaseIcb

      property_not_supported :expires_on


      property_not_supported :nameservers

    end

  end
end
