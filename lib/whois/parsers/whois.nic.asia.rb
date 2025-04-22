#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias'


module Whois
  class Parsers

    # Parser for the whois.nic.asia server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicAsia < BaseAfilias

      self.scanner = Scanners::BaseAfilias, {
          pattern_reserved: /^Reserved by DotAsia\n/,
      }

      property_supported :status do
        if reserved?
          :reserved
        else
          Array(node("Domain Status"))
        end
      end

      # NEWPROPERTY
      def reserved?
        !!node("status:reserved")
      end

    end

  end
end
