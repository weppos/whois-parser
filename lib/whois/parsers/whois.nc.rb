#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.nc.rb'


module Whois
  class Parsers

    # Parser for the whois.nc server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNc < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisNc


      property_not_supported :disclaimer


      property_supported :domain do
        node("Domain")
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
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("Created on") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("Last updated on") { |value| parse_time(value) }
      end

      property_supported :expires_on do
        node("Expires on") { |value| parse_time(value) }
      end


      property_not_supported :registrar


      property_supported :registrant_contacts do
        node("Registrant name") do |str|
          address = []
          index   = 1
          while line = node("Registrant address #{index}")
            address << line
            index += 1
          end

          lines = address.dup
          country = lines[-1] =~ /(\d+)/ ? nil : lines.pop
          zip, city = lines.pop.match(/(\d+) (.+)/)[1, 2]

          Parser::Contact.new(
            :type         => Parser::Contact::TYPE_REGISTRANT,
            :id           => nil,
            :name         => node("Registrant name"),
            :organization => nil,
            :address      => lines.join("\n"),
            :city         => city,
            :zip          => zip,
            :state        => nil,
            :country      => country,
            :phone        => nil,
            :fax          => nil,
            :email        => nil
          )
        end
      end

      property_not_supported :admin_contacts

      property_not_supported :technical_contacts


      property_supported :nameservers do
        nameservers = []
        index = 1
        while line = node("Domain server #{index}")
          nameservers << line
          index += 1
        end

        nameservers.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end

    end

  end
end
