#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icb'


module Whois
  class Parsers

    # Parser for the whois.nic.io server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicIo < BaseIcb

      property_supported :domain do
        if reserved?
          nil
        else
          super()
        end
      end

      property_supported :status do
        if reserved?
          :reserved
        else
          super()
        end
      end


      # NEWPROPERTY
      def reserved?
        !!(content_for_scanner =~ /^Reserved by Registry\n/)
      end

    end

  end
end
