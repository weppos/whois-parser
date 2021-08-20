#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'

module Whois
  class Parsers

    # Parser for the whois.example.com server.
    #
    # In case you are not implementing all the methods,
    # please add the following statement to the class docblock.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    class WhoisNicGe < Base

      include Scanners::Scannable

      self.scanner = Scanners::Verisign

      # Gets the registry disclaimer that comes with the record.
      #
      # Returns a String with the disclaimer if available,
      # <tt>nil</tt> otherwise.
      property_supported :disclaimer do
        nil
      end

      # Gets the domain name as stored by the registry.
      #
      # Returns a String with the domain name if available,
      # <tt>nil</tt> otherwise.
      property_supported :domain do
        if content_for_scanner =~ /No match for\s\"(.+)\"\.\n/
          $1.downcase
        else
          node("Domain Name", &:downcase)
        end
      end

      # Gets the unique domain ID as stored by the registry.
      #
      # Returns a String with the domain ID if available,
      # <tt>nil</tt> otherwise.
      property_supported :domain_id do
        raise Whois::AttributeNotSupported
      end

      # Gets the record status or statuses.
      #
      # Returns a String/Array with the record status if available,
      # <tt>nil</tt> otherwise.
      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      # Checks whether this record is available.
      #
      # Returns true/false depending whether this record is available.
      property_supported :available? do
        !!(content_for_scanner =~ /^No match for/)
      end

      # Checks whether this record is registered.
      #
      # Returns true/false depending this record is available.
      property_supported :registered? do
        !available?
      end

      # Gets the date the record was created,
      # according to the registry record.
      #
      # Returns a Time object representing the date the record was created or
      # <tt>nil</tt> otherwise.
      property_supported :created_on do
        node("Creation Date") { |value| parse_time(value) }
      end

      # Gets the date the record was last updated,
      # according to the registry record.
      #
      # Returns a Time object representing the date the record was last updated or
      # <tt>nil</tt> if not available.
      property_supported :updated_on do
        nil
      end

      # Gets the date the record is set to expire,
      # according to the registry record.
      #
      # Returns a Time object representing the date the record is set to expire or
      # <tt>nil</tt> if not available.
      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end

      # Gets the registrar object containing the registrar details
      # extracted from the registry record.
      #
      # Returns an instance of <tt>Parser::Registrar</tt> representing the registrar or
      # <tt>nil</tt> if not available.
      property_supported :registrar do
        if node("Registrar")
          Parser::Registrar.new(
            name: node("Registrar"),
          )
        end
      end


      # Gets the registrant contact object containing the details of the record owner
      # extracted from the registry record.
      #
      # Returns an instance of <tt>Parser::Contact</tt> representing the registrant contact or
      # <tt>nil</tt> if not available.
      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      # Gets the administrative contact object containing the details of the record administrator
      # extracted from the registry record.
      #
      # Returns an instance of <tt>Parser::Contact</tt> representing the administrative contact or
      # <tt>nil</tt> if not available.
      property_supported :admin_contacts do
        build_contact("Admin", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      # Gets the technical contact object containing the details of the technical representative
      # extracted from the registry record.
      #
      # Returns an instance of <tt>Parser::Contact</tt> representing the technical contact or
      # <tt>nil</tt> if not available.
      property_supported :technical_contacts do
        build_contact("Tech", Parser::Contact::TYPE_TECHNICAL)
      end


      # Gets the list of name server entries for this record,
      # extracted from the registry record.
      #
      # @example
      #   nameserver
      #   # => []
      #
      # @example
      #   nameserver
      #   # => [
      #   #     #<struct Parser::Nameserver name="ns1.google.com">,
      #   #     #<struct Parser::Nameserver name="ns2.google.com">
      #   #    ]
      #
      # @return [Array<Parser::Nameserver>]
      property_supported :nameservers do
        Array.wrap(node("Name Server")).reject(&:empty?).reverse.map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end

      private

      def build_contact(element, type)
          if type == Parser::Contact::TYPE_REGISTRANT
            node(element) do
              Parser::Contact.new(
                type: type,
                name: node("#{element}"),
              )
            end
          elsif Parser::Contact::TYPE_ADMINISTRATIVE
            Parser::Contact.new(
              type: type,
              name: node("Admin Name"),
              email: node("Admin Email")
            )
          elsif Parser::Contact::TYPE_TECHNICAL
            Parser::Contact.new(
              type: type,
              name: node("Tech Name"),
              email: node("Tech Email")
            )
          end
        end
    end

  end
end
