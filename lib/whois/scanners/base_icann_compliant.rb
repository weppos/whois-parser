require_relative 'base'

module Whois
  module Scanners

    # Scanner for the Icann Compliant-based records.
    class BaseIcannCompliant < Base

      self.tokenizers += [
          :skip_head,
          :scan_available,
          :scan_reserved,
          :scan_throttled,
          :scan_keyvalue,
          :skip_blank_line,
          :scan_disclaimer,
          :skip_end,
      ]

      tokenizer :scan_available do
        if settings[:pattern_available] && @input.skip_until(settings[:pattern_available])
          @ast['status:available'] = true
          @ast["Domain Name"] ||= @input[1] # Regexp first capture group if any
        end
      end

      tokenizer :scan_throttled do
        if settings[:pattern_throttled] && @input.skip_until(settings[:pattern_throttled])
          @ast['response:throttled'] = true
        end
      end

      tokenizer :scan_reserved do
        if settings[:pattern_reserved] && @input.skip_until(settings[:pattern_reserved])
          @ast["status:reserved"] = true
        end
      end

      tokenizer :skip_head do
        if @input.skip_until(/Domain Name:/)
          @input.scan(/\s?(.+)\n/)
          @ast["Domain Name"] = @input[1].strip
        end
      end

      tokenizer :skip_end do
        @input.terminate
      end

      tokenizer :scan_disclaimer do
        if @input.match?(settings[:pattern_disclaimer] || /^The Service is provided/)
          @ast["field:disclaimer"] = _scan_lines_to_array(/^(.+)\n+/).join(" ")
        end
      end

    end

  end
end
