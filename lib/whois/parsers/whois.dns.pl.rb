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

    # Parser for the whois.dns.pl server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisDnsPl < Base

      property_supported :domain do
        if content_for_scanner =~ /DOMAIN NAME:\s+(.+)\n/
          ::Regexp.last_match(1)
        end
      end

      property_not_supported :domain_id


      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^No information available about domain name/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /created:\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /last modified:\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /renewal date:\s+(.+?)\n/ && ::Regexp.last_match(1) != "not defined"
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :registrar do
        match = content_for_scanner.slice(/REGISTRAR:\n((.+\n)+)\n/, 1)
        return unless match

        lines = match.split("\n")
        Parser::Registrar.new(name: lines[0])
      end

      property_not_supported :registrant_contacts

      property_not_supported :admin_contacts

      property_supported :technical_contacts do
        build_contact("TECHNICAL CONTACT", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        content_for_scanner.scan(/nameservers:\s+(.+)\n(.+)\n/).flatten.map do |line|
          line.strip!
          if line =~ /(.+) \[(.+)\]/
            Parser::Nameserver.new(:name => ::Regexp.last_match(1).chomp("."), :ipv4 => ::Regexp.last_match(2))
          else
            Parser::Nameserver.new(:name => line.chomp("."))
          end
        end
      end

      # Checks whether the response has been throttled.
      #
      # @return [Boolean]
      #
      # @example
      #   Looup quota exceeded.
      #
      def response_throttled?
        !!(content_for_scanner =~ /^request limit exceeded for/)
      end


      private

      def build_contact(element, type)
        match = content_for_scanner.slice(/#{element}:\n((.+\n)+)\n/, 1)
        return unless match

        values = parse_contact_block(match.split("\n"))
        zip, city = values["city"].match(/(.+?) (.+)/)[1..2]

        Parser::Contact.new(
          :type         => type,
          :id           => values["handle"],
          :name         => nil,
          :organization => values["company"],
          :address      => values["street"],
          :city         => city,
          :zip          => zip,
          :state        => nil,
          :country_code => values["location"],
          :phone        => values["phone"],
          :fax          => values["fax"],
          :email        => nil
        )
      end

      def parse_contact_block(lines)
        key  = nil
        hash = {}
        lines.each do |line|
          if line =~ /(.+):(.+)/
            hash[key = ::Regexp.last_match(1)] = ::Regexp.last_match(2).strip
          else
            hash[key] += "\n#{line.strip}"
          end
        end
        hash
      end

    end

  end
end
