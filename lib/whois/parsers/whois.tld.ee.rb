#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_whoisd'
require 'whois/scanners/base_whoisd'


module Whois
  class Parsers

    # Parser for the whois.tld.ee server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisTldEe < BaseWhoisd
    end

  end
end
