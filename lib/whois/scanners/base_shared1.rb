require_relative 'base'

module Whois
  module Scanners

    class BaseShared1 < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_reserved,
          :scan_keyvalue,
      ]


      tokenizer :scan_available do
        if @input.skip(/^No Data Found\n/)
          @ast["status:available"] = true
        end
      end

      tokenizer :scan_reserved do
        if settings[:pattern_reserved] && @input.scan(settings[:pattern_reserved])
          @ast["status:reserved"] = true
        end
      end

    end

  end
end
