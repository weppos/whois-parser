require_relative 'base_whoisd'

module Whois
  module Scanners

    class WhoisNicCz < BaseWhoisd

      self.tokenizers += [
          :scan_response_throttled,
      ]

      tokenizer :scan_response_throttled do
        if @input.match?(/Your connection limit exceeded\. Please slow down and try again later/)
          @ast["response:throttled"] = true
          @input.skip(/^.+\n/)
        end
      end

    end

  end
end
