require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.dns.hr record.
    class WhoisDnsHr < Base

      self.tokenizers += [
          :skip_empty_line,
          :skip_whois_dns_hr,
          :scan_available,
          :scan_disclaimer,
          :scan_keyvalue,
      ]

      tokenizer :scan_disclaimer do
        if @input.match?(/^\%(.*?)\n/)
          @ast["disclaimer"] = _scan_lines_to_array(/\%(.*?)\n/).select { |line| line =~ /\w+/ }.join(" ")
        end
      end

      tokenizer :skip_whois_dns_hr do
        @input.skip(/^# whois\.dns\.hr\n/)
      end

      tokenizer :scan_available do
        if @input.skip(/^%ERROR: no entries found\n/)
          @ast["status:available"] = true
        end
      end

    end

  end
end
