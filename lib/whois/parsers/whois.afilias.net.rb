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

    # Parser for the whois.afilias.net server.
    class WhoisAfiliasNet < BaseAfilias

      self.scanner = Scanners::BaseAfilias, {
          pattern_reserved: /^(Name is reserved by afilias\n)|(Reserved by the registry.\n)/,
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
