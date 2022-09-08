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

    # Parser for the whois.ja.net server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisJaNet < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^No such domain (.+)/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /^Entry created:\n\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /^Entry updated:\n\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /^Renewal date:\n\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Servers:\n((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |line|
            name, ipv4 = line.strip.downcase.split("\t")
            Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
          end
        end
      end

    end

  end
end
