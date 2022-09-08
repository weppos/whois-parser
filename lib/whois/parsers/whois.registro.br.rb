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

    # Parser for the whois.registro.br server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisRegistroBr < Base

      property_supported :domain do
        if available?
          content_for_scanner.match(/^% No match for \s*(.+)\n/)[1]
        else
          content_for_scanner.match(/^domain: \s*(.+)\n/)[1]
        end
      end


      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /No match for/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /created:\s+(.+?)(\s+#.+)?\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /changed:\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /expires:\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :registrant_contacts do
        parse_contact("owner-c", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        parse_contact("admin-c", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        parse_contact("tech-c", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |line|
          name, ipv4 = line.strip.split(" ")
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
      end


      private

      def parse_contact(element, type)
        return unless content_for_scanner =~ /#{element}:\s+(.+)\n/

        id = ::Regexp.last_match(1)
        content_for_scanner.scan(/nic-hdl-br:\s+#{id}\n((.+\n)+)\n/).any? ||
            Whois.bug!(ParserError, "Unable to parse contact block for nic-hdl-br: #{id}")
        values = build_hash(::Regexp.last_match(1).scan(/(.+?):\s+(.+?)\n/))

        created_on = values["created"] ? Time.utc(*values["created"][0..3], *values["created"][4..5], *values["created"][6..7]) : nil
        updated_on = values["changed"] ? Time.utc(*values["changed"][0..3], *values["changed"][4..5], *values["changed"][6..7]) : nil

        Parser::Contact.new({
          type:       type,
          id:         id,
          name:       values["person"],
          email:      values["e-mail"],
          created_on: created_on,
          updated_on: updated_on,
        })
      end

      def build_hash(tokens)
        {}.tap do |hash|
          tokens.each do |key, value|
            hash[key] = value
          end
        end
      end
    end

  end
end
