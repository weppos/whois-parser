# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "whois/parser/version"

Gem::Specification.new do |s|
  s.name        = "whois-parser"
  s.version     = Whois::Parser::VERSION
  s.authors     = ["Simone Carletti"]
  s.email       = ["weppos@weppos.net"]
  s.homepage    = "https://whoisrb.org/"
  s.summary     = "A pure Ruby WHOIS parser."
  s.description = "Whois Parser is a WHOIS parser written in pure Ruby. It can parse and convert responses into easy-to-use Ruby objects."
  s.license     = "MIT"

  s.required_ruby_version = ">= 2.3"

  s.require_paths    = %w( lib )
  s.files            = `git ls-files`.split("\n")
  s.test_files       = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.extra_rdoc_files = %w( LICENSE.txt .yardopts )

  s.add_dependency "whois", ">= 4.1.0"
  s.add_dependency "activesupport", ">= 4"

  s.add_development_dependency "rake"
  s.add_development_dependency "rspec"
  s.add_development_dependency "yard"
end