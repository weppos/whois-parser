#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/base_whoisd'


module Whois
  class Parsers

    # Base parser for Whoisd servers.
    #
    # @abstract
    class BaseWhoisd < Base
      include Scanners::Scannable

      class_attribute :status_mapping

      self.status_mapping = {
        "paid and in zone" => :registered,
        "expired" => :expired,
      }
      self.scanner = Scanners::BaseWhoisd


      property_supported :domain do
        node('domain')
      end

      property_not_supported :domain_id


      property_supported :status do
        node('status') do |value|
          status = Array(value).each do |s|
            v = self.class.status_mapping[s.downcase]
            break v if v
          end
          status || Whois::Parser.bug!(ParserError, "Unknown status `#{string}'.")
        end || :available
      end

      property_supported :available? do
        !!node('status:available')
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node('registered') { |string| parse_time(string) }
      end

      property_supported :updated_on do
        node('changed') { |string| parse_time(string) }
      end

      property_supported :expires_on do
        node('expire') { |string| parse_time(string) }
      end


      property_supported :registrar do
        node('registrar') do |string|
          Parser::Registrar.new(
              :id           => string,
              :name         => string
          )
        end
      end

      property_supported :registrant_contacts do
        node('registrant') do |value|
          build_contact(value, Parser::Contact::TYPE_REGISTRANT)
        end
      end

      property_supported :admin_contacts do
        node('admin-c') do |value|
          build_contact(value, Parser::Contact::TYPE_ADMINISTRATIVE)
        end
      end

      property_supported :technical_contacts do
        id = node_nsset['tech-c'] rescue nil
        if id
          build_contact(id, Parser::Contact::TYPE_TECHNICAL)
        end
      end


      property_supported :nameservers do
        lines = node_nsset['nserver'] rescue nil
        Array(lines).map do |line|
          if line =~ /(.+) \((.+)\)/
            name = ::Regexp.last_match(1)
            ipv4, ipv6 = ::Regexp.last_match(2).split(', ')
            Parser::Nameserver.new(:name => name, :ipv4 => ipv4, :ipv6 => ipv6)
          else
            Parser::Nameserver.new(:name => line.strip)
          end
        end
      end


      private

      def node_nsset
        node("node:nsset/#{node('nsset')}")
      end

      def build_contact(element, type)
        node("node:contact/#{element}") do |hash|
          address = hash['street'] || hash['address']
          address = address.join("\n") if address.respond_to?(:join)

          Parser::Contact.new(
              :type           => type,
              :id             => element,
              :name           => hash['name'],
              :organization   => hash['org'],
              :address        => address,
              :city           => hash['city'],
              :zip            => hash['postal code'],
              :country_code   => hash['country'],
              :phone          => hash['phone'],
              :email          => hash['e-mail'],
              :created_on     => parse_time(hash['created'])
          )
        end
      end

    end

  end
end
