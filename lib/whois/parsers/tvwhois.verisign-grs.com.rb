#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_verisign'


module Whois
  class Parsers

    # Parser for the tvwhois.verisign-grs.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class TvwhoisVerisignGrsCom < BaseVerisign
    end

  end
end
