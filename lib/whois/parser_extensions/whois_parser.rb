require 'whois'


module Whois
  class ParserExtensions

    module WhoisParser

      # Lazy-loads and returns the parser proxy for current record.
      #
      # @return [Whois::Record::Parser]
      def parser
        @parser ||= Parser.new(self)
      end

    end

  end
end


Whois::Record.class_eval do
  include Whois::ParserExtensions::WhoisParser
end
