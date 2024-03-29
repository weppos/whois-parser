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

    # Parser for the whois.nic.lk server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicLk < Base

      property_not_supported :disclaimer


      property_supported :domain do
        if content_for_scanner =~ /Domain Name:\n\s+(.+)\n/
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
        !!(content_for_scanner =~ /^This Domain is not available/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Created on\.+:(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Record last updated on\.+:(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Expires on\.+:(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_not_supported :registrar


      property_supported :registrant_contacts do
        if content_for_scanner =~ /Registrant:\n\s+(.+)\n/
          Parser::Contact.new(
            :type         => Parser::Contact::TYPE_REGISTRANT,
            :id           => nil,
            :name         => ::Regexp.last_match(1),
            :organization => nil,
            :address      => nil,
            :city         => nil,
            :zip          => nil,
            :state        => nil,
            :country      => nil,
            :country_code => nil,
            :phone        => nil,
            :fax          => nil,
            :email        => nil
          )
        end
      end

      property_not_supported :admin_contacts

      property_not_supported :technical_contacts

      property_supported :nameservers do
        if content_for_scanner =~ /Domain Servers in listed order:\n((?:.+\n)+)/
          ::Regexp.last_match(1).split("\n").map do |name|
            Parser::Nameserver.new(:name => name.strip.chomp("."))
          end
        end
      end

    end

  end
end
