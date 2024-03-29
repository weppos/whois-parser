module ParserExampleGroup

  def load_part(path)
    Whois::Record::Part.new(File.read(fixture("responses", @host.to_s, @suffix.to_s, @schema.to_s, path)), @host)
  end

end

RSpec::Matchers.define :cache_property do |property|
  match do |instance|
    cache = instance.instance_eval do
      @cached_properties = {}
      @cached_properties
    end

    expect(cache.key?(property)).to eq(false)
    value = instance.send(property)

    expect(cache.key?(property)).to eq(true)
    expect(cache[property]).to eq(value)

    true
  end

  failure_message_for_should do |instance|
    "expected parser to cache property #{property}"
  end
  failure_message_for_should_not do |instance|
    "expected parser to not cache property #{property}"
  end
end

RSpec.configure do |c|
  def c.escaped_path(*parts)
    /#{parts.join('\/')}/
  end

  c.include ParserExampleGroup, file_path: c.escaped_path(%w[spec whois parsers])
end
