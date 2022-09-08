require_relative 'base'

module Whois
  module Scanners

    # Scanner for WhoisTldEe-based records.
    class WhoisTldEe < Base

      self.tokenizers += [
          :scan_available,
          :skip_head,
          :scan_section,
          :skip_empty_line,
          :scan_disclaimer,
      ]


      tokenizer :scan_available do
        if @input.skip(/^Domain not found/)
          @ast['status:available'] = true
        end
      end

      tokenizer :scan_section do
        if @input.scan(/^(Domain|Registrant|Administrative contact|Technical contact|Registrar|Name servers|DNSSEC):?\n/)
          @tmp['_section'] = @input[1]
          while scan_keyvalue
          end
          @tmp.delete('_section')
        end
      end

      tokenizer :skip_head do
        @input.skip(/^Estonia .ee Top Level Domain WHOIS server\n\n/)
      end

      tokenizer :skip_end do
        @input.skip(%r{^More information at http://internet.ee\n?})
      end

      tokenizer :scan_disclaimer do
        @input.skip_until(/^(Estonia .ee Top Level Domain WHOIS server)/m)
        @ast['field:disclaimer'] = @input[1] << @input.scan_until(/.*$/m)
      end
    end
  end
end
