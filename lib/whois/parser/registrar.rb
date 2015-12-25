require_relative 'super_struct'


module Whois
  class Parser

    # Holds the details of the Registrar extracted from the WHOIS response.
    #
    # A registrar is composed by the several attributes,
    # accessible through corresponding getter / setter methods.
    #
    # Please note that a response is not required to provide
    # all the attributes. When an attribute is not available,
    # the corresponding value is set to nil.
    #
    # @attr [String] id
    # @attr [String] name
    # @attr [String] organization
    # @attr [String] url
    #
    class Registrar < SuperStruct.new(:id, :name, :organization, :url)
    end

  end
end
