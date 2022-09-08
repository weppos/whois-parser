require_relative 'base'

module Whois
  module Scanners

    # Scanner for the IIS.se company.
    class BaseIisse < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_disclaimer,
          :scan_keyvalue,
      ]


      tokenizer :scan_available do
        if @input.skip(/^(domain )?"(.+)" not found.+\n/)
          @ast["status:available"] = true
        end
      end

      tokenizer :scan_disclaimer do
        if @input.match?(/# Copyright/)
          lines = []
          while @input.scan(/#(.*)\n\n?/) # rubocop:disable Style/WhileUntilModifier
            lines << @input[1].strip if @input[1].strip != ""
          end
          @ast["field:disclaimer"] = lines.join(" ")
        end
      end

    end

  end
end
