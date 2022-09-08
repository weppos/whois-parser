#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias2'


module Whois
  class Parsers

    # Parser for the whois.nic.xxx server.
    class WhoisNicXxx < BaseAfilias2

      self.scanner = Scanners::BaseAfilias, {
          pattern_disclaimer: /^Access to/,
          pattern_reserved: /^Reserved by ICM Registry\n/,
      }


      property_supported :status do
        if reserved?
          :reserved
        else
          super()
        end
      end


      # NEWPROPERTY
      def reserved?
        !!node("status:reserved")
      end

    end

  end
end
