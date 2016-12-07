#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'za_central_registry'


module Whois
  class Parsers

    # Parser for the coza-whois.registry.za.net server.
    #
    class CozaWhoisRegistryNetZa < ZaCentralRegistry
    end

  end
end
