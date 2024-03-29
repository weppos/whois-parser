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

    # Parser for the whois.ua server.
    class WhoisUa < Base

      class Uaepp
        attr_reader :parent, :content

        def initialize(parent, content)
          @parent  = parent
          @content = content
        end

        def status
          if content =~ /status:\s+(.+?)\n/
            case (s = ::Regexp.last_match(1).downcase)
            when "ok", "clienthold", "autorenewgraceperiod", "clienttransferprohibited"
              :registered
            when "redemptionperiod", "pendingdelete"
              :redemption
            else
              Whois::Parser.bug!(ParserError, "Unknown status `#{s}'.")
            end
          else
            :available
          end
        end

        def created_on
          if content =~ /created:\s+(.+)\n/
            Base.parse_time(::Regexp.last_match(1))
          end
        end

        def updated_on
          if content =~ /modified:\s+(.+)\n/
            Base.parse_time(::Regexp.last_match(1))
          end
        end

        def expires_on
          if content =~ /expires:\s+(.+)\n/
            Base.parse_time(::Regexp.last_match(1))
          end
        end


        def build_contact(element, type)
          contact_ids = content.scan(/#{element}:\s+(.+)\n/).flatten
          return if contact_ids.empty?

          contact_ids.map do |contact_id|
            textblock = content.slice(/contact-id:\s+#{contact_id}\n((?:.+\n)+)\n/, 1)

            address = textblock.scan(/address:\s+(.+)\n/).flatten
            address = address.reject { |a| a == "n/a" }

            Parser::Contact.new(
              type:         type,
              id:           contact_id,
              name:         textblock.slice(/person:\s+(.+)\n/, 1),
              organization: textblock.slice(/organization:\s+(.+)\n/, 1),
              address:      address.join("\n"),
              zip:          nil,
              state:        nil,
              city:         nil,
              country:      textblock.slice(/country:\s+(.+)\n/, 1),
              phone:        textblock.slice(/phone:\s+(.+)\n/, 1),
              fax:          textblock.slice(/fax:\s+(.+)\n/, 1),
              email:        textblock.slice(/e-mail:\s+(.+)\n/, 1),
              created_on:   Base.parse_time(textblock.slice(/created:\s+(.+)\n/, 1))
            )
          end
        end
      end

      class Uanic
        attr_reader :parent, :content

        def initialize(parent, content)
          @parent  = parent
          @content = content
        end

        def status
          if content =~ /status:\s+(.+?)\n/
            case (s = ::Regexp.last_match(1).downcase)
            when /^ok-until/
              :registered
            else
              Whois::Parser.bug!(ParserError, "Unknown status `#{s}'.")
            end
          else
            :available
          end
        end

        def created_on
          if content =~ /created:\s+(.+)\n/
            time = ::Regexp.last_match(1).split(" ").last
            Base.parse_time(time)
          end
        end

        def updated_on
          if content =~ /changed:\s+(.+)\n/
            time = ::Regexp.last_match(1).split(" ").last
            Base.parse_time(time)
          end
        end

        def expires_on
          if content =~ /status:\s+(.+)\n/
            time = ::Regexp.last_match(1).split(" ").last
            Base.parse_time(time)
          end
        end


        def build_contact(element, type)
          contact_ids = content.scan(/#{element}:\s+(.+)\n/).flatten
          return if contact_ids.empty?

          contact_ids.map do |contact_id|
            textblock = content.slice(/nic-handle:\s+#{contact_id}\n((?:.+\n)+)\n/, 1)

            address = textblock.scan(/address:\s+(.+)\n/).flatten
            zip = nil
            zip = address[1].slice!(/\s+\d{5}/).strip if address[1] =~ /\s+\d{5}/
            zip = address[1].slice!(/\d{5}\s+/).strip if address[1] =~ /\d{5}\s+/
            state = nil
            state = address[1].slice!(/\s+[A-Z]{2}\z/).strip if address[1] =~ /\s+[A-Z]{2}\z/

            Parser::Contact.new(
              type:         type,
              id:           contact_id,
              name:         nil,
              organization: textblock.scan(/organization:\s+(.+)\n/).join("\n"),
              address:      address[0],
              zip:          zip,
              state:        state,
              city:         address[1],
              country:      address[2],
              phone:        textblock.slice(/phone:\s+(.+)\n/, 1),
              fax:          textblock.slice(/fax-no:\s+(.+)\n/, 1),
              email:        textblock.slice(/e-mail:\s+(.+)\n/, 1),
              updated_on:   (Base.parse_time(::Regexp.last_match(1).split(" ").last) if textblock =~ /changed:\s+(.+)\n/)
            )
          end
        end
      end


      property_supported :domain do
        if content_for_scanner =~ /domain:\s+(.+)\n/
          ::Regexp.last_match(1)
        end
      end

      property_not_supported :domain_id


      property_supported :status do
        subparser.status
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^% No entries found for/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        subparser.created_on
      end

      property_supported :updated_on do
        subparser.updated_on
      end

      property_supported :expires_on do
        subparser.expires_on
      end


      property_not_supported :registrar

      property_supported :registrant_contacts do
        subparser.build_contact("registrant", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :admin_contacts do
        subparser.build_contact("admin-c", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        subparser.build_contact("tech-c", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(name: name.strip)
        end
      end


      private

      def subparser
        @subparser ||= begin
          source = content_for_scanner.slice(/source:\s+(.+)\n/, 1)
          if source == "UANIC"
            Uanic.new(self, content_for_scanner)
          else
            Uaepp.new(self, content_for_scanner)
          end
        end
      end

    end

  end
end
