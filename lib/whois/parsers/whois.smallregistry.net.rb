#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.smallregistry.net.rb'


module Whois
  class Parsers

    # Parser for the whois.smallregistry.net server.
    #
    # @author Mathieu Arnold <m@absolight.fr>
    #
    class WhoisSmallregistryNet < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisSmallregistryNet


      property_supported :disclaimer do
        node("field:disclaimer") do |alpha|
          alpha.scan(/# (.+)\n/).flatten.map do |beta|
            token = beta.strip
            token.gsub!(/\s+/, " ")
          end.join(" ").gsub!(/(\s{2})/, "\n")
        end
      end


      property_supported :domain do
        node("name")
      end

      property_not_supported :domain_id


      property_supported :status do
        if node?("status:available")
          :available
        else
          case node("status")
          when "ACTIVE"
            :registered
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{node('field:status')}'.")
          end
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("created") { |str| parse_time(str) }
      end

      property_supported :updated_on do
        node("updated") { |str| parse_time(str) }
      end

      property_supported :expires_on do
        node("expired") { |str| parse_time(str) }
      end


      property_supported :registrar do
        node("registrar") do |hash|
          Parser::Registrar.new(
              :name         => hash['name'],
              :url          => hash['web']
          )
        end
      end

      property_supported :registrant_contacts do
        build_contact("registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("administrative_contact", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("technical_contact", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        Array(node("name_servers")).map do |hash|
          Parser::Nameserver.new(:name => hash)
        end
      end


      private

      def build_contact(element, type)
        node(element) do |hash|
          Parser::Contact.new(
            :type         => type,
            :id           => hash['nic-handle'],
            :name         => hash['name'],
            :organization => hash['company'],
            :address      => hash['address'],
            :phone        => hash['phone'],
            :fax          => hash['fax'],
            :email        => hash['mobile'],
            :updated_on   => parse_time(hash['updated'])
          )
        end
      end

    end
  end
end
