#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca'


module Whois
  class Parsers

    # Parser for the whois.netcom.cm server.
    class WhoisNetcomCm < BaseCocca

      status_mapping.merge!({
          "suspended" => :registered,
      })

    end

  end
end
