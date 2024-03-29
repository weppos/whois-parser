require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.fi record.
    class WhoisFi < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_disclaimer,
          :scan_keyvalue,
          :scan_reserved,
      ]


      tokenizer :scan_available do
        if @input.skip(/^Domain not found/)
          @ast["status:available"] = true
        end
      end

      tokenizer :scan_reserved do
        if @input.skip(/^Domain not available/)
          @ast["status:reserved"] = true
        end
      end

      tokenizer :scan_disclaimer do
        if @input.match?(/^More information/)
          @ast["field:disclaimer"] = @input.scan_until(/(.*)\n\n/).strip
        end
      end

    end

  end
end
