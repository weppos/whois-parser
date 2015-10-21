#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias'


module Whois
  class Parsers

    # Parser for the whois.registrypro.pro server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisRegistryproPro < BaseAfilias

      property_supported :status do
        if reserved?
          :reserved
        else
          super()
        end
      end

      # NEWPROPERTY
      def reserved?
        !!content_for_scanner.match(/Governmental Reserved Name/)
      end

    end

  end
end
