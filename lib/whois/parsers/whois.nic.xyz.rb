#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'whois.centralnic.com.rb'


module Whois
  class Parsers

    # Parser for the whois.nic.xyz server.
    class WhoisNicXyz < WhoisCentralnicCom
    end

  end
end
