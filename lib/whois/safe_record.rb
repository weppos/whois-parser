require_relative 'parser'

module Whois
  class SafeRecord < BasicObject

    # @api private
    def self.define_property_method(method)
      class_eval <<-RUBY, __FILE__, __LINE__ + 1
        def #{method}(*args, &block)
          if property_any_supported?(:#{method})
            parser.#{method}(*args, &block)
          end
        end
      RUBY
    end

    # @api private
    def self.define_method_method(method)
      class_eval <<-RUBY, __FILE__, __LINE__ + 1
        def #{method}(*args, &block)
          if parser.respond_to?(:#{method})
            parser.#{method}(*args, &block)
          end
        end
      RUBY
    end

    # @api private
    def self.define_question_method(method)
      return if method.to_s.end_with?("?")

      class_eval <<-RUBY, __FILE__, __LINE__ + 1
        def #{method}?
          !#{method}.nil?
        end
      RUBY
    end

    Parser::PROPERTIES.each do |method|
      define_property_method(method)
    end

    Parser::METHODS.each do |method|
      define_method_method(method)
    end

    (Parser::PROPERTIES + Parser::METHODS).each do |method|
      define_question_method(method)
    end


    attr_reader :record

    def initialize(record)
      @record = record
    end

    alias target record


    # Checks if this class respond to given method.
    #
    # Overrides the default implementation to add support
    # for {Whois::Parser::PROPERTIES} and {Whois::Parser::METHODS}.
    #
    # @return [Boolean]
    #
    def respond_to?(*args)
      respond_to_parser_method?(args.first) || target.respond_to?(*args)
    end


    # Lazy-loads and returns the parser proxy for current record.
    #
    # @return [Whois::Parser]
    def parser
      @parser ||= Parser.new(record)
    end

    # Returns a Hash containing all supported properties for this record
    # along with corresponding values.
    #
    # @return [{ Symbol => Object }]
    def properties
      hash = {}
      Parser::PROPERTIES.each do |property|
        hash[property] = __send__(property)
      end
      hash
    end

    # Shortcut for <tt>#registrant_contacts.first</tt>.
    #
    # @see Whois::Parser#registrant_contacts
    #
    # @return [Whois::Parser::Contact]
    #         If the property is supported and a contact exists.
    # @return [nil]
    #         If the property is not supported or the contact doesn't exist.
    def registrant_contact
      if property_any_supported?(:registrant_contacts)
        registrant_contacts.first
      end
    end

    # Shortcut for <tt>#admin_contacts.first</tt>.
    #
    # @see Whois::Parser#admin_contacts
    #
    # @return [Whois::Parser::Contact]
    #         If the property is supported and a contact exists.
    # @return [nil]
    #         If the property is not supported or the contact doesn't exist.
    def admin_contact
      if property_any_supported?(:admin_contacts)
        admin_contacts.first
      end
    end

    # Shortcut for <tt>#technical_contacts.first</tt>.
    #
    # @see Whois::Parser#technical_contacts
    #
    # @return [Whois::Parser::Contact]
    #         If the property is supported and a contact exists.
    # @return [nil]
    #         If the property is not supported or the contact doesn't exist.
    def technical_contact
      if property_any_supported?(:technical_contacts)
        technical_contacts.first
      end
    end

    # Collects and returns all the contacts.
    #
    # @see Whois::Parser#contacts
    #
    # @return [Array<Whois::Parser::Contact>]
    def contacts
      parser.contacts
    end


    private

    # @api private
    def respond_to_parser_method?(symbol)
      name = symbol.to_s =~ /\?$/ ? symbol.to_s[0..-2] : symbol
      Parser::PROPERTIES.include?(name.to_sym) || Parser::METHODS.include?(name.to_sym)
    end

    # Checks if the property passed as symbol
    # is supported in any of the parsers.
    #
    # @api private
    # @see Whois::Parser::Parser#property_any_supported?
    #
    # @param  [Symbol] property The name of the property to check.
    # @return [Boolean]
    def property_any_supported?(property)
      parser.property_any_supported?(property)
    end

    # Delegates any missing method to Record.
    def method_missing(method, *args, &block)
      target.send(method, *args, &block)
    end

  end
end
