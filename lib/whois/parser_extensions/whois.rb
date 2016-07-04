require 'whois'


module Whois
  class ParserExtensions

    module Whois
      def self.included(base)
        base.extend ClassMethods
      end

      module ClassMethods
        # Checks whether the object represented by <tt>object</tt> is available.
        #
        # Warning: this method is only available if a Whois parser exists
        # for the top level domain of <tt>object</tt>.
        # If no parser exists for <tt>object</tt>, you'll receive a
        # warning message and the method will return <tt>nil</tt>.
        # This is a technical limitation. Browse the lib/whois/record/parsers
        # folder to view all available parsers.
        #
        # @param  [String] object The string to be sent as query parameter.
        #         It is intended to be a domain name, otherwise this method
        #         may return unexpected responses.
        # @return [Boolean]
        #
        # @example
        #   Whois.available?("google.com")
        #   # => false
        #
        # @example
        #   Whois.available?("google-is-not-available-try-again-later.com")
        #   # => true
        #
        def available?(object)
          result = lookup(object).available?
          if result.nil?
            warn  "This method is not supported for this kind of object.\n" +
                  "Use Whois.lookup('#{object}') instead."
          end
          result
        end

        # Checks whether the object represented by <tt>object</tt> is registered.
        #
        # Warning: this method is only available if a Whois parser exists
        # for the top level domain of <tt>object</tt>.
        # If no parser exists for <tt>object</tt>, you'll receive a warning message
        # and the method will return <tt>nil</tt>.
        # This is a technical limitation. Browse the lib/whois/record/parsers folder
        # to view all available parsers.
        #
        # @param  [String] object The string to be sent as query parameter.
        #         It is intended to be a domain name, otherwise this method
        #         may return unexpected responses.
        # @return [Boolean]
        #
        # @example
        #   Whois.registered?("google.com")
        #   # => true
        #
        # @example
        #   Whois.registered?("google-is-not-available-try-again-later.com")
        #   # => false
        #
        def registered?(object)
          result = lookup(object).registered?
          if result.nil?
            warn  "This method is not supported for this kind of object.\n" +
                  "Use Whois.lookup('#{object}') instead."
          end
          result
        end
      end
    end

  end
end


Whois.class_eval do
  include Whois::ParserExtensions::Whois
end
