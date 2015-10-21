#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require 'whois'


module Whois
  class ParserExtensions

    module WhoisRecord
      def self.included(base)
        base.extend ClassMethods
      end

      # Checks if this class respond to given method.
      #
      # Overrides the default implementation to add support
      # for {Parser::PROPERTIES} and {Parser::METHODS}.
      #
      # @return [Boolean]
      #
      def respond_to?(symbol, include_private = false)
        respond_to_parser_method?(symbol) || super
      end


      # Lazy-loads and returns the parser proxy for current record.
      #
      # @return [Whois::Record::Parser]
      #
      def parser
        @parser ||= Parser.new(self)
      end

      # Checks if the <tt>property</tt> passed as symbol
      # is supported in any of the parsers.
      #
      # @param  [Symbol] property The name of the property to check.
      # @return [Boolean]
      #
      # @see Whois::Record::Parser#property_any_supported?
      #
      def property_any_supported?(property)
        parser.property_any_supported?(property)
      end


      # @!group Properties

      # Returns a Hash containing all supported properties for this record
      # along with corresponding values.
      #
      # @return [{ Symbol => Object }]
      #
      def properties
        hash = {}
        Parser::PROPERTIES.each { |property| hash[property] = send(property) }
        hash
      end

      # @!endgroup


      # @!group Methods

      # Shortcut for <tt>#registrant_contacts.first</tt>.
      #
      # @return [Whois::Record::Contact]
      #         If the property is supported and a contact exists.
      # @return [nil]
      #         If the property is not supported or the contact doesn't exist.
      #
      # @see Whois::Record#registrant_contacts
      #
      def registrant_contact
        if property_any_supported?(:registrant_contacts)
          parser.registrant_contacts.first
        end
      end

      # Shortcut for <tt>#admin_contacts.first</tt>.
      #
      # @return [Whois::Record::Contact]
      #         If the property is supported and a contact exists.
      # @return [nil]
      #         If the property is not supported or the contact doesn't exist.
      #
      # @see Whois::Record#admin_contacts
      #
      def admin_contact
        if property_any_supported?(:admin_contacts)
          parser.admin_contacts.first
        end
      end

      # Shortcut for <tt>#technical_contacts.first</tt>.
      #
      # @return [Whois::Record::Contact]
      #         If the property is supported and a contact exists.
      # @return [nil]
      #         If the property is not supported or the contact doesn't exist.
      #
      # @see Whois::Record#technical_contacts
      #
      def technical_contact
        if property_any_supported?(:technical_contacts)
          parser.technical_contacts.first
        end
      end

      # Collects and returns all the contacts.
      #
      # @return [Array<Whois::Record::Contact>]
      #
      # @see Whois::Record::Parser#contacts
      #
      def contacts
        parser.contacts
      end

      # @!endgroup


      # @!group Response

      # Checks whether this {Whois::Record} is different than +other+.
      #
      # Comparing the {Whois::Record} content is not as trivial as you may think.
      # WHOIS servers can inject into the WHOIS response strings that changes at every request,
      # such as the timestamp the request was generated or the number of requests left
      # for your current IP.
      #
      # These strings causes a simple equal comparison to fail even if
      # the registry data is the same.
      #
      # This method should provide a bulletproof way to detect whether this record
      # changed compared with +other+.
      #
      # @param  [Whois::Record] other The other record instance to compare.
      # @return [Boolean]
      #
      # @see Whois::Record::Parser#changed?
      #
      def changed?(other)
        !unchanged?(other)
      end

      # The opposite of {#changed?}.
      #
      # @param  [Whois::Record] other The other record instance to compare.
      # @return [Boolean]
      #
      # @see Whois::Record::Parser#unchanged?
      #
      def unchanged?(other)
        unless other.is_a?(self.class)
          raise(ArgumentError, "Can't compare `#{self.class}' with `#{other.class}'")
        end

        equal?(other) || parser.unchanged?(other.parser)
      end


      # Checks whether this is an incomplete response.
      #
      # @return [Boolean]
      #
      # @see Whois::Record::Parser#response_incomplete?
      #
      def response_incomplete?
        parser.response_incomplete?
      end

      # Checks whether this is a throttle response.
      #
      # @return [Boolean]
      #
      # @see Whois::Record::Parser#response_throttled?
      #
      def response_throttled?
        parser.response_throttled?
      end

      # Checks whether this is an unavailable response.
      #
      # @return [Boolean]
      #
      # @see Whois::Record::Parser#response_unavailable?
      #
      def response_unavailable?
        parser.response_unavailable?
      end

      # @!endgroup

      def respond_to_parser_method?(symbol)
        name = symbol.to_s =~ /\?$/ ? symbol.to_s[0..-2] : symbol
        Parser::PROPERTIES.include?(name.to_sym) || Parser::METHODS.include?(name.to_sym)
      end

      # Delegates all method calls to the internal parser.
      def method_missing(method, *args, &block)
        if Parser::PROPERTIES.include?(method)
          self.class.define_property_method(method)
          send(method, *args, &block)
        elsif Parser::METHODS.include?(method)
          self.class.define_method_method(method)
          send(method, *args, &block)
        elsif method.to_s =~ /([a-z_]+)\?/ and (Parser::PROPERTIES + Parser::METHODS).include?($1.to_sym)
          self.class.define_question_method($1)
          send(method)
        else
          super
        end
      end

      module ClassMethods
        # @api private
        def define_property_method(method)
          class_eval <<-RUBY, __FILE__, __LINE__ + 1
            def #{method}(*args, &block)
              if property_any_supported?(:#{method})
                parser.#{method}(*args, &block)
              end
            end
          RUBY
        end

        # @api private
        def define_method_method(method)
          class_eval <<-RUBY, __FILE__, __LINE__ + 1
            def #{method}(*args, &block)
              if parser.respond_to?(:#{method})
                parser.#{method}(*args, &block)
              end
            end
          RUBY
        end

        # @api private
        def define_question_method(method)
          class_eval <<-RUBY, __FILE__, __LINE__ + 1
            def #{method}?
              !#{method}.nil?
            end
          RUBY
        end
      end
    end

  end
end
