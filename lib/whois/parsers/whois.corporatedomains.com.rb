#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icann_compliant'


module Whois
  class Parsers

    # Parser for the whois.corporatedomains.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisCorporatedomainsCom < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^No match for/
      }

      property_supported :created_on do
        node("Creation Date") do |value|
          if value.include?("/")
            parse_time_with_slash_format(value)
          else
            parse_time(value)
          end
        end
      end

      property_supported :expires_on do
        node("Registrar Registration Expiration Date") do |value|
          if value.include?("/")
            parse_time_with_slash_format(value)
          else
            parse_time(value)
          end
        end
      end

      private

      # There are 2 different date formats which are used for creation and expiration dates:
      #   - hyphen-separated date format YYYY-MM-DDTHH:MM:SSZ
      #   - slash-separated date format MM/DD/YYYY HH:MM:SS
      #
      # The latter format causes problems because `parse_time` parsed as (DD/MM/YYYY HH:MM:SS), so it needs
      # to be parsed differently.
      def parse_time_with_slash_format(value)
        date, time = value.split
        month, day, year = date.split("/")

        Time.utc(year, month, day, time)
      end
    end

  end
end
