#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require_relative 'whois.centralnic.com.rb'


module Whois
  class Parsers

    # Parser for the whois.nic.la server.
    #
    # It aliases the whois.centralnic.com parser because
    # the .LA TLD is powered by Centralnic.
    class WhoisNicLa < WhoisCentralnicCom
    end

  end
end
