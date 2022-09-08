#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_whoisd'
require 'whois/scanners/whois.nic.cz.rb'


module Whois
  class Parsers

    # Parser for the whois.nic.cz server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicCz < BaseWhoisd

      self.scanner = Scanners::WhoisNicCz

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end


      def response_throttled?
        !!node("response:throttled")
      end

    end

  end
end
