require_relative 'parser_extensions/whois'
require_relative 'parser_extensions/whois_record'

Whois.class_eval do
  include Whois::ParserExtensions::Whois
end
Whois::Record.class_eval do
  include Whois::ParserExtensions::WhoisRecord
end
