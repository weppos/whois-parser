module Whois

  # @!group Parser

  # Generic class for parser errors.
  class ParserError < Error
  end

  # Raised when the library hasn't been able to load a valid parser
  # according to current settings and you're trying to access a property
  # that requires a valid parser.
  class ParserNotFound < ParserError
  end

  # Raised when you are trying to access an attribute that has not been implemented.
  class AttributeNotImplemented < ParserError
  end

  # Raised when you are trying to access an attribute that is not supported.
  class AttributeNotSupported < ParserError
  end

  # @!endgroup


  # @!group Response

  # Generic class for response errors.
  class ResponseError < Error
  end

  # Raised when attempting to access a property when the response is throttled.
  #
  # @see Whois::Parsers::Base#response_throttled?
  class ResponseIsThrottled < ResponseError
  end

  # Raised when attempting to access a property when the response is unavailable.
  #
  # @see Whois::Parsers::Base#response_unavailable?
  class ResponseIsUnavailable < ResponseError
  end

  # @!endgroup

end
