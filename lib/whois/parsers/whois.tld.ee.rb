#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++

require_relative 'base'
require 'whois/scanners/whois.tld.ee'

module Whois
  class Parsers

    # Parser for the whois.tld.ee server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisTldEe < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisTldEe


      property_supported :disclaimer do
        node('field:disclaimer').to_s.strip
      end


      property_supported :domain do
        if content_for_scanner =~ /^Domain:\nname:\s+(.+)\n/
          ::Regexp.last_match(1).to_s.strip.downcase
        end
      end

      property_not_supported :domain_id


      property_supported :status do
        if content_for_scanner =~ /status:\s+(.+?)\n/
          case ::Regexp.last_match(1)
          when 'ok (paid and in zone)'
            :registered
          when 'expired'
            :expired
          else
            ::Regexp.last_match(1)
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!node('status:available')
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /registered:\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /changed:\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /expire:\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :registrar do
        node('Registrar') do |hash|
          Parser::Registrar.new(
            name:         hash['name'],
            url:          hash['url']
          )
        end
      end

      property_supported :registrant_contacts do
        build_contact('Registrant', Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact('Administrative contact', Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact('Technical contact', Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        node('Name servers') do |hash|
          Array(hash['nserver']).map do |name|
            Parser::Nameserver.new(name: name.downcase)
          end
        end
      end


      private

      def build_contact(element, type)
        node(element) do |hash|
          el_size = Array(hash['name']).size

          (0...el_size).map do |i|
            Parser::Contact.new(
              type:       type,
              name:       Array(hash['name'])[i],
              email:      Array(hash['email'])[i],
              updated_on: parse_time(Array(hash['changed'])[i])
            )
          end
        end
      end

    end
  end
end
