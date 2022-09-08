require_relative 'base'

module Whois
  module Scanners

    class WhoisYoursrsCom < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_keyvalue,
      ]


      tokenizer :scan_available do
        if @input.scan(/^No match for [\w.]+/)
          @ast["status:available"] = true
        end
      end

    end

  end
end
