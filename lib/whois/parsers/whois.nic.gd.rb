#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_shared3'


module Whois
  class Parsers

    # Parser for the whois.nic.gd server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicGd < BaseShared3

      # NEWPROPERTY
      def reserved?
        !!content_for_scanner.match(/RESTRICTED/)
      end

    end

  end
end
