require_relative 'base'

module Whois
  module Scanners

    # Scanner for the Afilias-based records.
    class BaseAfilias < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_reserved,
          :scan_throttled,
          :scan_disclaimer,
          :scan_keyvalue,
      ]


      tokenizer :scan_available do
        if @input.scan(/^(NOT FOUND|No Data Found)\n/)
          @ast["status:available"] = true
        end
      end

      tokenizer :scan_reserved do
        if settings[:pattern_reserved] && @input.scan(settings[:pattern_reserved])
          @ast["status:reserved"] = true
        end
      end

      # .ORG
      tokenizer :scan_throttled do
        if @input.match?(/.*LIMIT EXCEEDED/)
          @ast["response:throttled"] = true
          @input.skip(/^.+\n/)
        end
      end

      tokenizer :scan_disclaimer do
        if @input.match?(/^Access to/)
          @ast["field:disclaimer"] = _scan_lines_to_array(/^(.+)\n+/).join(" ")
        end
      end
    end

  end
end
