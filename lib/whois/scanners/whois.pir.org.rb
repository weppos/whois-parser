require_relative 'base'

module Whois
  module Scanners

    # Scanner for the Afilias-based records.
    class WhoisPirOrg < BaseAfilias

      tokenizer :scan_disclaimer do
        if @input.match?(/^Access to/)
          @ast["field:disclaimer"] = _scan_lines_to_array(/^(.+)(\n+)/).join(" ")
        end
      end
    end

  end
end
