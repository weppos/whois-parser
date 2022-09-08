#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_whoisd'


module Whois
  class Parsers

    # Parser for the whois.tznic.or.tz server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisTznicOrTz < BaseWhoisd
    end

  end
end
