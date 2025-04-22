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

    # Parser for the whois.jprs.jp server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisJprsJp < Base

      property_supported :status do
        if content_for_scanner =~ /\[Status\]\s+(.+)\n/
          case ::Regexp.last_match(1).downcase
          when "active"
            :registered
          when "reserved"
            :reserved
          when "to be suspended"
            :redemption
          when "suspended"
            :expired
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        elsif content_for_scanner =~ /\[State\]\s+(.+)\n/
          case ::Regexp.last_match(1).split(" ").first.downcase
          when "connected", "registered"
            :registered
          when "deleted"
            :suspended
          when "reserved"
            :reserved
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /No match!!/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /\[(?:Created on|Registered Date)\][ \t]+(.*)\n/
          (::Regexp.last_match(1).empty?) ? nil : parse_time(::Regexp.last_match(1), timezone: 'Asia/Tokyo')
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /\[Last Updated?\][ \t]+(.*)\n/
          (::Regexp.last_match(1).empty?) ? nil : parse_time(::Regexp.last_match(1), timezone: 'Asia/Tokyo')
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /\[(?:Expires on|State)\][ \t]+(.*)\n/
          (::Regexp.last_match(1).empty?) ? nil : parse_time(::Regexp.last_match(1), timezone: 'Asia/Tokyo')
        end
      end

      property_supported :registrar do
        name = nil
        organization = nil
        url = nil
        
        if content_for_scanner =~ /\[Registrant\][ \t]+(.*)\n/
          name = ::Regexp.last_match(1)
        end
        
        if content_for_scanner =~ /\[Name\][ \t]+(.*)\n/
          organization = ::Regexp.last_match(1)
        end
        
        if content_for_scanner =~ /\[Web Page\][ \t]+(.*)\n/ && !::Regexp.last_match(1).strip.empty?
          url = ::Regexp.last_match(1).strip
        end
        
        Parser::Registrar.new(
          id: nil,
          name: name,
          organization: organization,
          url: url
        )
      end

      property_supported :nameservers do
        content_for_scanner.scan(/\[Name Server\][\s\t]+([^\s\n]+?)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end


      # NEWPROPERTY
      def reserved?
        status == :reserved
      end

    end

  end
end
