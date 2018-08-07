require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.auda.org.au record.
    class WhoisAudaOrgAu < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :skip_lastupdate,
          :scan_disclaimer,
          :scan_keyvalue,
      ]

      tokenizer :scan_available do
        if @input.skip(/^(No Data Found)|(NOT FOUND)\n/)
          @ast["status:available"] = true
        end
      end

      tokenizer :skip_lastupdate do
        @input.skip(/>>>(.+?)<<<\n/)
      end

      tokenizer :scan_disclaimer do
        if @input.match?(/^(Afilias Australia Pty Ltd)(.+)\n\n/)
          @ast["field:disclaimer"] = _scan_lines_to_array(/(.+)(\n+)/).join("\n")
        end
      end
    end

  end
end
