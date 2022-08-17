#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'whois.centralnic.com'


module Whois
  class Parsers

    # Parser for the whois.nic.fun server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicFun < WhoisCentralnicCom
    end

  end
end


