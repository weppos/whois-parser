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

    #
    # = whois.isoc.org.il parser
    #
    # Parser for the whois.isoc.org.il server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisIsocOrgIl < Base

      property_supported :status do
        if content_for_scanner =~ /status:\s+(.*?)\n/
          case ::Regexp.last_match(1).downcase
          when "transfer locked"
            :registered
          when "transfer allowed"
            :registered
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        !available?
      end


      # TODO: first changed record
      property_not_supported :created_on

      property_supported :updated_on do
        if content_for_scanner =~ /changed:\s+(.+)\n/
          t = content_for_scanner.scan(/changed:\s+(?:.+?) (\d+) \(.+\)\n/).flatten.last
          parse_time(t)
        end
      end

      property_not_supported :expires_on


      property_supported :nameservers do
        content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name.strip)
        end
      end

    end

  end
end
