#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_verisign'


module Whois
  class Parsers

    # Parser for the whois.verisign-grs.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisVerisignGrsCom < BaseVerisign

      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end


      property_supported :registrar do
        node("Registrar") do |value|
          Parser::Registrar.new(
              id:           last_useful_item(node("Registrar IANA ID")),
              name:         last_useful_item(value),
              url:          referral_url
          )
        end
      end

      # Checks whether this response contains a message
      # that can be reconducted to a "WHOIS Server Unavailable" status.
      #
      # @return [Boolean]
      def response_unavailable?
        !!node("response:unavailable")
      end

    end

  end
end
