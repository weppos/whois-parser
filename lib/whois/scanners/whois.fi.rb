require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.fi record.
    class WhoisFi < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_keyvalue,
          :scan_reserved,
          :scan_section,
          :scan_keyvalue,
          :skip_last_update,
          :scan_disclaimer
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

      tokenizer :scan_section do
        if @input.scan(/^(Nameservers|DNSSEC|Holder|Registrar|Tech)\n\n/)
          @tmp['_section'] = @input[1]
          while scan_keyvalue
          end
          @tmp.delete('_section')
        end
      end

      # Override scan_keyvalue to match the weird
      # key.........: value -format
      tokenizer :scan_keyvalue do
        if @input.scan(/(.+?)(\.+):(.*?)(\n|\z)/)
          key, value = @input[1].strip, @input[3].strip
          target = @tmp['_section'] ? (@ast[@tmp['_section']] ||= {}) : @ast

          if target[key].nil?
            target[key] = value
          else
            target[key] = Array(target[key])
            target[key] << value
          end
        end
      end

      tokenizer :skip_last_update do
        @input.skip(/^>>> Last update.*<<<\n\n/)
      end

      tokenizer :scan_disclaimer do
        @input.skip_until(/^(Copyright \(c\) Finnish Transport and Communications Agency Traficom)/)
        @ast["field:disclaimer"] = @input[1]
      end

    end
  end
end
