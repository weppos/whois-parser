#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_shared2'


module Whois
  class Parsers

    # Parser for the whois.nic.co server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicCo < BaseShared2
      property_supported :available? do
        !!content_for_scanner.match(/No Data Found/)
      end
    end

  end
end
