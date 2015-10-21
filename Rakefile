require 'rubygems'

module Whois; end
require_relative 'lib/whois/parser/version'


# Run test by default.
task :default => :spec
task :test => :spec

spec = Gem::Specification.new do |s|
  s.name              = "whois-parser"
  s.version           = Whois::Parser::VERSION
  s.summary           = "An intelligent pure Ruby WHOIS parser."
  s.description       = "Whois is an intelligent WHOIS parser written in pure Ruby. It can parse and convert responses into easy-to-use Ruby objects."

  s.required_ruby_version = ">= 2.0.0"

  s.authors           = ["Simone Carletti"]
  s.email             = ["weppos@weppos.net"]
  s.homepage          = "http://whoisrb.org/"
  s.license           = "MIT"

  s.files             = %w( LICENSE.txt .yardopts ) +
                        Dir.glob("*.{markdown,gemspec}") +
                        Dir.glob("{lib}/**/*")
  s.require_paths     = %w( lib )

  # s.add_dependency "whois", ">= 4.0.0"
  s.add_dependency "activesupport", ">= 3"

  s.add_development_dependency "rake"
  s.add_development_dependency "rspec", "~> 3.0"
  s.add_development_dependency "mocha"
  s.add_development_dependency "yard"
end


require 'rubygems/package_task'

Gem::PackageTask.new(spec) do |pkg|
  pkg.gem_spec = spec
end

desc "Build the gemspec file #{spec.name}.gemspec"
task :gemspec do
  file = File.dirname(__FILE__) + "/#{spec.name}.gemspec"
  File.open(file, "w") {|f| f << spec.to_ruby }
end

desc "Remove any temporary products, including gemspec"
task :clean => [:clobber] do
  rm "#{spec.name}.gemspec" if File.file?("#{spec.name}.gemspec")
end

desc "Remove any generated file"
task :clobber => [:clobber_package]

desc "Package the library and generates the gemspec"
task :package => [:gemspec]


require 'rspec/core/rake_task'
begin
  require 'fuubar'
rescue LoadError
end

RSpec::Core::RakeTask.new do |t|
  t.verbose = !!ENV["VERBOSE"]
  t.rspec_opts  = []
  t.rspec_opts << ['--format', 'Fuubar'] if defined?(Fuubar)
end


require 'yard'

YARD::Rake::YardocTask.new(:yardoc) do |y|
  y.options = ["--output-dir", "yardoc"]
end

namespace :yardoc do
  task :clobber do
    rm_r "yardoc" rescue nil
  end
end

task :clobber => "yardoc:clobber"


desc "Open an irb session preloaded with this library"
task :console do
  sh "irb -rubygems -I lib -r whois/parser.rb"
end


Dir["tasks/**/*.rake"].each do |file|
  load(file)
end
