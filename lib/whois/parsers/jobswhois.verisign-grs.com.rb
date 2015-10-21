#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_verisign'


module Whois
  class Parsers

    # Parser for the jobswhois.verisign-grs.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class JobswhoisVerisignGrsCom < BaseVerisign
    end

  end
end