#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require 'whois'
require 'active_support'
require 'active_support/core_ext/object/blank'
require 'active_support/core_ext/class/attribute'
require 'active_support/core_ext/time/calculations'

require_relative 'parser/version'
require_relative 'parser/errors'

# These extensions add Whois::Record#parser, the Whois.registered?, and
# Whois.available? shortcuts.
# These are handy convenient methods, and they are loaded by default.
require_relative 'parser_extensions/whois'
require_relative 'parser_extensions/whois_parser'

# These extensions add most of Whois::Record parser-specific extensions
# that were loaded by default in Whois 3. This is not recommended as it adds
# a lot of stuff into the Whois::Record class.
# Instead of Whois::Record.foo you should just use Whois::Record.parser.foo
# and add your own abstraction if you need to manipulate the results.
require_relative 'parser_extensions' if ENV["WHOISRB_4EXTENSIONS"] == "1"

# This is really not recommended. It will restore Whois 3 old behavior
# where the record was silently swallowing the error (returnin nil)
# when the property was not implemented or not supported.
# This compatibility layer will likely be removed in future releases.
# See https://github.com/weppos/whois-parser/pull/5
# require_relative 'safe_record'

# This is required at the end of the file
# because it depends on Whois::Parser::PROPERTIES
# require_relative 'parsers'

# The parsing controller that stays behind the {Whois::Record}.
#
# It provides object-oriented access to a WHOIS response.
# The list of properties and methods is available
# in the following constants:
#
# * {Whois::Parser::METHODS}
# * {Whois::Parser::PROPERTIES}
#
module Whois
  class Parser

    # Appends `Please report issue to` to the message
    # and raises a new +error+ with the final message.
    #
    # @param  [Exception] error
    # @param  [String] message
    # @return [void]
    #
    # @api private
    # @private
    def self.bug!(error, message)
      raise error, message.dup          +
          " Please report the issue at" +
          " http://github.com/weppos/whois-parser/issues"
    end

    METHODS = [
      :contacts,
      :changed?, :unchanged?,
      # :response_incomplete?, :response_throttled?, :response_unavailable?,
      # :referral_whois, :referral_url,
    ]

    PROPERTIES = [
      :disclaimer,
      :domain, :domain_id,
      :status, :available?, :registered?,
      :created_on, :updated_on, :expires_on,
      :registrar,
      :registrant_contacts, :admin_contacts, :technical_contacts,
      :nameservers,
    ]

    PROPERTY_STATE_NOT_IMPLEMENTED = :not_implemented
    PROPERTY_STATE_NOT_SUPPORTED = :not_supported
    PROPERTY_STATE_SUPPORTED = :supported


    # Instanciate the proper parser instance for given <tt>part</tt>.
    # The parser class is determined using <tt>.parser_for</tt>
    #
    # @param  [Whois::Record::Part] part The part to get the parser for.
    #
    # @return [Whois::Parsers::Base]
    #         An instance of the specific parser for given part.
    #         The instance is expected to be a child of {Whois::Parsers::Base}.
    #
    # @example
    #
    #   # Parser for a known host
    #   Parser.parser_for("whois.example.com")
    #   # => #<Whois::Parsers::WhoisExampleCom>
    #
    #   # Parser for an unknown host
    #   Parser.parser_for("missing.example.com")
    #   # => #<Whois::Parsers::Blank>
    #
    def self.parser_for(part)
      parser_klass(part).new(part)
    end

    # Detects the proper parser class according to given <tt>part</tt>
    # and returns the class constant.
    # The parser class is selected according to the values of the
    # <tt>#host</tt> and <tt>#body</tt> attributes for given <tt>part</tt>.
    #
    # This method autoloads missing parser classes. If you want to define
    # a custom parser, simple make sure the class is loaded in the Ruby
    # environment before this method is called.
    #
    # @param  [Whois::Record::Part] part The part to get the parser for.
    #
    # @return [Class] The instance of Class representing the parser Class
    #         corresponding to <tt>part</tt>. If <tt>part</tt> doesn't have
    #         a specific parser implementation, then returns
    #         the {Whois::Parsers::Blank} {Class}.
    #         The {Class} is expected to be a child of {Whois::Parsers::Base}.
    #
    # @example
    #
    #   Parser.parser_klass(Whois::Record::Part.new(host: "whois.example.com"))
    #   # => Whois::Parsers::WhoisExampleCom
    #
    def self.parser_klass(part)
      autoload(part.host)
    rescue LoadError
      # Some WHOIS services like Donuts Inc covers hundred of TLDs (https://donuts.domains/what-we-do/top-level-domain-portfolio/)
      # But using one host per TLD, so in this case it's easier to match on the disclaimer directly to cover all hosts
      if part.body&.include?("Terms of Use: Identity Digital Inc.")
        autoload("donuts_inc")
      elsif part.body&.include?("The Whois and RDAP services are provided by CentralNic")
        autoload("central_nic")
      else
        autoload("blank")
      end
    end

    # Converts <tt>host</tt> to the corresponding parser class name.
    #
    # @param  [String] host The server host.
    # @return [String] The class name.
    #
    # @example
    #
    #   Parser.host_to_parser("whois.nic.it")
    #   # => "WhoisNicIt"
    #
    #   Parser.host_to_parser("whois.nic-info.it")
    #   # => "WhoisNicInfoIt"
    #
    def self.host_to_parser(host)
      host.to_s.downcase
          .gsub(/[.-]/, '_')
          .gsub(/(?:^|_)(.)/) { ::Regexp.last_match(1).upcase }
          .gsub(/\A(\d+)\z/)  { "Host#{::Regexp.last_match(1)}" }
    end

    # Requires the file at <tt>whois/parsers/#{name}</tt>.
    #
    # @param  [String] name The file name to load.
    #
    # @return [void]
    #
    def self.autoload(name)
      class_name = host_to_parser(name)
      require_relative "parsers/#{name}.rb" unless Parsers.const_defined?(class_name)
      Parsers.const_get(class_name)
    end


    # @return [Whois::Record] The record referenced by this parser.
    attr_reader :record


    # Initializes and return a new parser from +record+.
    #
    # @param  [Whois::Record] record
    #
    def initialize(record)
      @record = record
    end

    # Checks if this class respond to given method.
    #
    # Overrides the default implementation to add support
    # for {PROPERTIES} and {METHODS}.
    #
    # @return [Boolean]
    def respond_to?(symbol, include_private = false)
      respond_to_parser_method?(symbol) || super
    end


    # Returns an array with all host-specific parsers initialized for the parts
    # contained into this parser.
    # The array is lazy-initialized.
    #
    # @return [Array<Whois::Parsers::Base>]
    #
    def parsers
      @parsers ||= init_parsers
    end

    # Checks if the <tt>property</tt> passed as symbol
    # is supported in any of the parsers.
    #
    # @return [Boolean]
    #
    # @see Whois::Parsers::Base.property_supported?
    #
    def property_any_supported?(property)
      parsers.any? { |parser| parser.property_supported?(property) }
    end

    # Checks if the <tt>property</tt> passed as symbol
    # is "not implemented" in any of the parsers.
    #
    # @return [Boolean]
    #
    def property_any_not_implemented?(property)
      parsers.any? { |parser| parser.class.property_state?(property, Whois::Parser::PROPERTY_STATE_NOT_IMPLEMENTED) }
    end


    # @!group Methods

    # Collects and returns all the contacts from all the record parts.
    #
    # @return [Array<Whois::Record::Contact>]
    #
    # @see Whois::Record#contacts
    # @see Whois::Parsers::Base#contacts
    #
    def contacts
      parsers.map(&:contacts).flatten
    end

    # @!endgroup


    # @!group Response

    # Loop through all the record parts to check
    # if at least one part changed.
    #
    # @param  [Whois::Parser] other The other parser instance to compare.
    # @return [Boolean]
    #
    # @see Whois::Record#changed?
    # @see Whois::Parsers::Base#changed?
    #
    def changed?(other)
      !unchanged?(other)
    end

    # The opposite of {#changed?}.
    #
    # @param  [Whois::Parser] other The other parser instance to compare.
    # @return [Boolean]
    #
    # @see Whois::Record#unchanged?
    # @see Whois::Parsers::Base#unchanged?
    #
    def unchanged?(other)
      unless other.is_a?(self.class)
        raise(ArgumentError, "Can't compare `#{self.class}' with `#{other.class}'")
      end

      equal?(other) ||
      (parsers.size == other.parsers.size && all_in_parallel?(parsers, other.parsers) { |one, two| one.unchanged?(two) })
    end


    # Loop through all the parts to check if at least
    # one part is an incomplete response.
    #
    # @return [Boolean]
    #
    # @see Whois::Record#response_incomplete?
    # @see Whois::Parsers::Base#response_incomplete?
    #
    def response_incomplete?
      any_is?(parsers, :response_incomplete?)
    end

    # Loop through all the parts to check if at least
    # one part is a throttle response.
    #
    # @return [Boolean]
    #
    # @see Whois::Record#response_throttled?
    # @see Whois::Parsers::Base#response_throttled?
    #
    def response_throttled?
      any_is?(parsers, :response_throttled?)
    end

    # Loop through all the parts to check if at least
    # one part is an unavailable response.
    #
    # @return [Boolean]
    #
    # @see Whois::Record#response_unavailable?
    # @see Whois::Parsers::Base#response_unavailable?
    #
    def response_unavailable?
      any_is?(parsers, :response_unavailable?)
    end

    # @!endgroup


    private

    # @api private
    def self.define_property_method(method)
      class_eval <<-RUBY, __FILE__, __LINE__ + 1
        def #{method}(*args, &block)
          delegate_property_to_parsers(:#{method}, *args, &block)
        end
      RUBY
    end

    # @api private
    def self.define_method_method(method)
      class_eval <<-RUBY, __FILE__, __LINE__ + 1
        def #{method}(*args, &block)
          delegate_method_to_parsers(:#{method}, *args, &block)
        end
      RUBY
    end

    def respond_to_parser_method?(symbol)
      PROPERTIES.include?(symbol) || METHODS.include?(symbol)
    end

    def method_missing(method, *args, &block)
      if PROPERTIES.include?(method)
        self.class.define_property_method(method)
        send(method, *args, &block)
      elsif METHODS.include?(method)
        self.class.define_method_method(method)
        send(method, *args, &block)
      else
        super
      end
    end

    def delegate_property_to_parsers(method, *args, &block)
      if parsers.empty?
        raise ParserError, "Unable to select a parser because the Record is empty"
      elsif (parser = select_parser { |p| p.class.property_state?(method, PROPERTY_STATE_SUPPORTED) })
        parser.send(method, *args, &block)
      elsif (parser = select_parser { |p| p.class.property_state?(method, PROPERTY_STATE_NOT_SUPPORTED) })
        parser.send(method, *args, &block)
      else
        raise AttributeNotImplemented, "Unable to find a parser for property `#{method}'"
      end
    end

    def delegate_method_to_parsers(method, *args, &block)
      if parsers.empty?
        raise ParserError, "Unable to select a parser because the Record is empty"
      elsif (parser = select_parser { |p| p.respond_to?(method) })
        parser.send(method, *args, &block)
      else
        nil
      end
    end

    # Loops through all record parts, for each part
    # tries to guess the appropriate parser object whenever available,
    # and returns the final array of server-specific parsers.
    #
    # Parsers are initialized in reverse order for performance reason.
    #
    # @return [Array<Class>] An array of Class,
    #         where each item is the parts reverse-N specific parser {Class}.
    #         Each {Class} is expected to be a child of {Whois::Parsers::Base}.
    #
    # @example
    #
    #   parser.parts
    #   # => [whois.foo.com, whois.bar.com]
    #
    #   parser.parsers
    #   # => [Whois::Parsers::WhoisBarCom, Whois::Parsers::WhoisFooCom]
    #
    # @api private
    def init_parsers
      record.parts.reverse.map { |part| self.class.parser_for(part) }
    end

    # Selects the first parser in {#parsers} where blocks evaluates to true.
    #
    # @return [Whois::Parsers::Base]
    #         The parser for which the block returns true.
    # @return [nil]
    #         If the parser wasn't found.
    #
    # @yield  [parser]
    #
    # @example
    #
    #   select_parser { |parser| parser.class.property_state?(:nameserver, :any) }
    #   # => #<Whois::Parsers::WhoisExampleCom>
    #   select_parser { |parser| parser.class.property_state?(:nameservers, PROPERTY_STATE_SUPPORTED) }
    #   # => nil
    #
    # @api private
    def select_parser(&block)
      parsers.each do |parser|
        return parser if block.call(parser)
      end
      nil
    end

    # @api private
    def all_in_parallel?(*args)
      count = args.first.size
      index = 0

      while index < count
        return false unless yield(*args.map { |arg| arg[index] })

        index += 1
      end
      true
    end

    # @api private
    def any_is?(collection, symbol)
      collection.any? { |item| item.is(symbol) }
    end

  end
end

require_relative 'parsers'
