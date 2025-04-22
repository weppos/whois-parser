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

    # Base parser for CoCCA servers.
    #
    # @abstract
    class BaseCocca < Base

      class_attribute :status_mapping

      self.status_mapping = {
        "active" => :registered,
        "delegated" => :registered,
        "not registered" => :available,
      }


      property_supported :domain do
        content_for_scanner =~ /Query:\s+(.+?)\n/
        ::Regexp.last_match(1) || Whois::Parser.bug!(ParserError, "Unable to parse domain.")
      end

      property_not_supported :domain_id


      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.+?)\n/
          status = ::Regexp.last_match(1).downcase
          self.class.status_mapping[status] || Whois::Parser.bug!(ParserError, "Unknown status `#{status}'.")
        else
          Whois::Parser.bug!(ParserError, "Unable to parse status.")
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        !available?
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


      property_supported :registrar do
        if content_for_scanner =~ /Registrar Name: (.+)\n/
          Parser::Registrar.new(
              name:         $1,
              url:          content_for_scanner.slice(/Registration URL: (.+)\n/, 1)
          )
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Name Servers:\n((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |name|
            Parser::Nameserver.new(:name => name.strip)
          end
        end
      end

    end

  end
end
