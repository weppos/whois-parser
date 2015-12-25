require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.audns.net.au record.
    class WhoisAudnsNetAu < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_keyvalue,
      ]


      tokenizer :scan_available do
        if @input.skip(/^No Data Found\n/)
          @ast["status:available"] = true
        end
      end

    end

  end
end
