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
      def respond_to_missing?(symbol, include_private = false)
        respond_to_parser_method?(symbol) || super
      end


      # Lazy-loads and returns the parser proxy for current record.
      #
      # @return [Whois::Record::Parser]
      def parser
        @parser ||= Parser.new(self)
      end

      # Returns a Hash containing all supported properties for this record
      # along with corresponding values.
      #
      # @return [{ Symbol => Object }]
      # @raise  [Whois::AttributeNotSupported, Whois::AttributeNotImplemented]
      def properties
        warn("#{self.class}#properties is deprecated")
        hash = {}
        Parser::PROPERTIES.each { |property| hash[property] = send(property) }
        hash
      end

      # Shortcut for <tt>#registrant_contacts.first</tt>.
      #
      # @see Whois::Record#registrant_contacts
      #
      # @return [Whois::Record::Contact]
      #         If the property is supported and a contact exists.
      # @return [nil]
      #         If the the contact doesn't exist.
      # @raise  [Whois::AttributeNotSupported, Whois::AttributeNotImplemented]
      def registrant_contact
        parser.registrant_contacts.first
      end

      # Shortcut for <tt>#admin_contacts.first</tt>.
      #
      # @see Whois::Record#admin_contacts
      #
      # @return [Whois::Record::Contact]
      #         If the property is supported and a contact exists.
      # @return [nil]
      #         If the contact doesn't exist.
      # @raise  [Whois::AttributeNotSupported, Whois::AttributeNotImplemented]
      def admin_contact
        parser.admin_contacts.first
      end

      # Shortcut for <tt>#technical_contacts.first</tt>.
      #
      # @see Whois::Record#technical_contacts
      #
      # @return [Whois::Record::Contact]
      #         If the property is supported and a contact exists.
      # @return [nil]
      #         If the contact doesn't exist.
      # @raise  [Whois::AttributeNotSupported, Whois::AttributeNotImplemented]
      def technical_contact
        parser.technical_contacts.first
      end

      # Collects and returns all the contacts.
      #
      # @see Whois::Parser#contacts
      #
      # @return [Array<Whois::Record::Contact>]
      def contacts
        warn("#{self.class}#contacts is deprecated")
        parser.contacts
      end


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
      # @see Whois::Parser#changed?
      #
      # @param  [Whois::Record] other The other record instance to compare.
      # @return [Boolean]
      def changed?(other)
        !unchanged?(other)
      end

      # The opposite of {#changed?}.
      #
      # @see Whois::Parser#unchanged?
      #
      # @param  [Whois::Record] other The other record instance to compare.
      # @return [Boolean]
      def unchanged?(other)
        unless other.is_a?(self.class)
          raise(ArgumentError, "Can't compare `#{self.class}' with `#{other.class}'")
        end

        equal?(other) || parser.unchanged?(other.parser)
      end

      # Checks whether this is an incomplete response.
      #
      # @deprecated
      # @see Whois::Parser#response_incomplete?
      #
      # @return [Boolean]
      def response_incomplete?
        warn("#{self.class}#response_incomplete? is deprecated. Use parser.response_incomplete?")
        parser.response_incomplete?
      end

      # Checks whether this is a throttle response.
      #
      # @deprecated
      # @see Whois::Parser#response_throttled?
      #
      # @return [Boolean]
      def response_throttled?
        warn("#{self.class}#response_throttled? is deprecated. Use parser.response_throttled?")
        parser.response_throttled?
      end

      # Checks whether this is an unavailable response.
      #
      # @deprecated
      # @see Whois::Parser#response_unavailable?
      #
      # @return [Boolean]
      def response_unavailable?
        warn("#{self.class}#response_unavailable? is deprecated. Use parser.response_unavailable?")
        parser.response_unavailable?
      end


      # @deprecated
      def property_any_supported?(property)
        warn("#{self.class}#property_any_supported? is deprecated and has no effect. Use Whois::Parser.property_any_supported? if you need it.")
      end


      private

      # @api private
      def respond_to_parser_method?(symbol)
        Parser::PROPERTIES.include?(symbol) ||
          Parser::METHODS.include?(symbol) ||
          respond_to_question_method?(symbol)
      end

      def respond_to_question_method?(symbol)
        return false unless symbol.to_s =~ /([a-z_]+)\?/

        symbol = ::Regexp.last_match(1).to_sym
        Parser::PROPERTIES.include?(symbol) ||
            Parser::METHODS.include?(symbol)
      end

      # Delegates all method calls to the internal parser.
      def method_missing(method, *args, &block)
        if Parser::PROPERTIES.include?(method)
          self.class.define_property_method(method)
          send(method, *args, &block)
        elsif Parser::METHODS.include?(method)
          self.class.define_method_method(method)
          send(method, *args, &block)
        elsif method.to_s =~ /([a-z_]+)\?/ and (Parser::PROPERTIES + Parser::METHODS).include?(::Regexp.last_match(1).to_sym)
          self.class.define_question_method(::Regexp.last_match(1))
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
              parser.#{method}(*args, &block)
            end
          RUBY
        end

        # @api private
        def define_method_method(method)
          class_eval <<-RUBY, __FILE__, __LINE__ + 1
            def #{method}(*args, &block)
              parser.#{method}(*args, &block)
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


Whois::Record.class_eval do
  include Whois::ParserExtensions::WhoisRecord
end
