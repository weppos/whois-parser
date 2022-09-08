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

    # Parser for the whois.kenic.or.ke server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisKenicOrKe < Base

      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.+?)\n/
          case ::Regexp.last_match(1).downcase
          when "active"
            :registered
          when "not registered"
            :available
          when "this whois server does not have any records for that zone."
            :invalid
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          Whois::Parser.bug!(ParserError, "Unable to parse status.")
        end
      end

      property_supported :available? do
        !invalid? && status == :available
      end

      property_supported :registered? do
        !invalid? && !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Created:\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Modified:\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Expires:\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Name Servers:\n((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |name|
            Parser::Nameserver.new(:name => name.strip)
          end
        end
      end


      # NEWPROPERTY
      def invalid?
        cached_properties_fetch(:invalid?) do
          status == :invalid
        end
      end

    end

  end
end
