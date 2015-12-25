require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.centralnic.com record.
    class WhoisCentralnicCom < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_disclaimer,
          :scan_keyvalue,
      ]


      tokenizer :scan_available do
        if @input.skip(/^DOMAIN NOT FOUND\n/)
          @ast["status:available"] = true
        end
      end

      tokenizer :scan_disclaimer do
        if @input.match?(/^\S([^:]+)\n/)
          @ast["field:disclaimer"] = _scan_lines_to_array(/(.+)\n/).join(" ")
        end
      end

    end

  end
end
