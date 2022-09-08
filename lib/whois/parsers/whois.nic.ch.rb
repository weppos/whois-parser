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
    # = whois.nic.ch parser
    #
    # Parser for the whois.nic.ch server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicCh < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /We do not have an entry/)
      end

      property_supported :registered? do
        !available?
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_not_supported :expires_on

      # Registrant is given in the following format:
      #
      #   Holder of domain name:
      #   Name
      #   Address line 1
      #   Address line 2
      #   Address line n
      #   Contractual Language: language
      #
      property_supported :registrant_contacts do
        if content_for_scanner =~ /Holder of domain name:\n(.+?)\n(.+?)\nContractual Language:.*\n\n/m
          Parser::Contact.new({ :name => ::Regexp.last_match(1), :address => ::Regexp.last_match(2), :type => Parser::Contact::TYPE_REGISTRANT })
        end
      end

      # Technical contact is given in the following format:
      #
      #   Technical contact:
      #   Name
      #   Address line 1
      #   Address line 2
      #   Address line n
      #
      property_supported :technical_contacts do
        if content_for_scanner =~ /Technical contact:\n(.+?)\n(.+?)\n\n/m
          Parser::Contact.new({ :name => ::Regexp.last_match(1), :address => ::Regexp.last_match(2), :type => Parser::Contact::TYPE_TECHNICAL })
        end
      end

      property_not_supported :admin_contacts

      # Nameservers are listed in the following formats:
      #
      #   ns1.citrin.ch
      #   ns1.citrin.ch  [193.247.72.8]
      #
      property_supported :nameservers do
        if content_for_scanner =~ /Name servers:\n((.+\n)+)(?:\n|\z)/
          list  = {}
          order = []
          ::Regexp.last_match(1).split("\n").map do |line|
            if line =~ /(.+)\t\[(.+)\]/
              name, ip = ::Regexp.last_match(1), ::Regexp.last_match(2)
              order << name unless order.include?(name)
              list[name] ||= Parser::Nameserver.new(:name => name)
              list[name].ipv4 = ip if Whois::Server.send(:valid_ipv4?, ip)
              list[name].ipv6 = ip if Whois::Server.send(:valid_ipv6?, ip)
            else
              order << line unless order.include?(line)
              list[line] ||= Parser::Nameserver.new(:name => line)
            end
          end
          order.map { |name| list[name] }
        end
      end
    end

  end
end
