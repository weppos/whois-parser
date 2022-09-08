#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'za_central_registry'


module Whois
  class Parsers

    # Parser for the whois.org.za parser server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class OrgWhoisRegistryNetZa < ZaCentralRegistry
    end

  end
end
