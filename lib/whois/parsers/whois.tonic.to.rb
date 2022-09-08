#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'


module Whois
  class Parsers

    # Parser for the whois.tonic.to server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    class WhoisTonicTo < Base

      property_not_supported :disclaimer


      property_not_supported :domain

      property_not_supported :domain_id


      property_supported :status do
        if response_incomplete?
          :incomplete
        elsif available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        (!response_incomplete? && !!(content_for_scanner =~ /No match for/))
      end

      property_supported :registered? do
        (!response_incomplete? && !available?)
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_not_supported :registrar


      property_not_supported :registrant_contacts

      property_not_supported :admin_contacts

      property_not_supported :technical_contacts


      property_not_supported :nameservers


      # Very often the .to server returns a partial response,
      # which is a response containing an empty line.
      # It seems to be a very poorly-designed throttle mechanism.
      #
      # @return [Boolean]
      #
      # @see Whois::Parsers::Base#response_incomplete?
      #
      def response_incomplete?
        content_for_scanner.strip == ""
      end

    end

  end
end
