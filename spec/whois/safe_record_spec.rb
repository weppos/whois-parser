require 'spec_helper'
require 'whois/safe_record'

describe Whois::SafeRecord do

  subject { described_class.new(record) }

  let(:record) {
    Whois::Record.new(server, parts)
  }
  let(:server) {
    Whois::Server.factory(:tld, ".foo", "whois.example.test")
  }
  let(:parts) {
    [
     Whois::Record::Part.new(body: "This is a record from foo.", host: "foo.example.test"),
     Whois::Record::Part.new(body: "This is a record from bar.", host: "bar.example.test"),
 ]
  }


  describe "#initialize" do
    it "sets the record" do
      expect(subject.record).to be(record)
    end
  end


  describe "#respond_to?" do
    before(:all) do
      @_properties  = Whois::Parser::PROPERTIES.dup
      @_methods     = Whois::Parser::METHODS.dup
    end

    after(:all) do
      Whois::Parser::PROPERTIES.clear
      Whois::Parser::PROPERTIES.push(*@_properties)
      Whois::Parser::METHODS.clear
      Whois::Parser::METHODS.push(*@_methods)
    end

    it "returns true if method is in self" do
      expect(subject.respond_to?(:to_s)).to eq(true)
    end

    it "returns true if method is in hierarchy" do
      expect(subject.respond_to?(:nil?)).to eq(true)
    end

    it "returns true if method is a property" do
      Whois::Parser::PROPERTIES << :test_property
      expect(subject.respond_to?(:test_property)).to eq(true)
    end

    it "returns true if method is a property?" do
      Whois::Parser::PROPERTIES << :test_property
      expect(subject.respond_to?(:test_property?)).to eq(true)
    end

    it "returns true if method is a method" do
      Whois::Parser::METHODS << :test_method
      expect(subject.respond_to?(:test_method)).to eq(true)
    end

    it "returns true if method is a method" do
      Whois::Parser::METHODS << :test_method
      expect(subject.respond_to?(:test_method?)).to eq(true)
    end
  end


  describe "#parser" do
    it "returns a Parser" do
      expect(subject.parser).to be_a(Whois::Parser)
    end

    it "initializes the parser with the record" do
      expect(subject.parser.record).to be(subject.record)
    end

    it "memoizes the value" do
      expect(subject.instance_eval { @parser }).to be_nil
      parser = subject.parser
      expect(subject.instance_eval { @parser }).to be(parser)
    end
  end

  describe "#properties" do
    it "returns a Hash" do
      expect(subject.properties).to be_a(Hash)
    end

    it "returns both nil and not-nil values" do
      expect(subject).to receive(:domain).and_return("")
      expect(subject).to receive(:created_on).and_return(nil)
      expect(subject).to receive(:expires_on).and_return(Time.parse("2010-10-10"))

      properties = subject.properties
      expect(properties[:domain]).to eq("")
      expect(properties[:created_on]).to be_nil
      expect(properties[:expires_on]).to eq(Time.parse("2010-10-10"))
    end

    it "fetches all parser property" do
      expect(subject.properties.keys).to match(Whois::Parser::PROPERTIES)
    end
  end

  describe "#contacts" do
    it "delegates to parser" do
      expect(subject.parser).to receive(:contacts).and_return([:one, :two])
      expect(subject.contacts).to eq([:one, :two])
    end
  end


  class Whois::Parsers::WhoisPropertiesTest < Whois::Parsers::Base
    property_supported :status do
      nil
    end
    property_supported :created_on do
      Date.parse("2010-10-20")
    end
    property_not_supported :updated_on
    # property_not_defined :expires_on
  end

  describe "property" do
    it "returns value when the property is supported" do
      instance = described_class.new(Whois::Record.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")]))
      expect(instance.created_on).to eq(Date.parse("2010-10-20"))
    end

    it "returns nil when the property is not supported" do
      instance = described_class.new(Whois::Record.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")]))
      expect(instance.updated_on).to be_nil
    end

    it "returns nil when the property is not implemented" do
      instance = described_class.new(Whois::Record.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")]))
      expect(instance.expires_on).to be_nil
    end
  end

  describe "property?" do
    it "returns true when the property is supported and has no value" do
      instance = described_class.new(Whois::Record.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")]))
      expect(instance.status?).to eq(false)
    end

    it "returns false when the property is supported and has q value" do
      instance = described_class.new(Whois::Record.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")]))
      expect(instance.created_on?).to eq(true)
    end

    it "returns false when the property is not supported" do
      instance = described_class.new(Whois::Record.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")]))
      expect(instance.updated_on?).to eq(false)
    end

    it "returns false when the property is not implemented" do
      instance = described_class.new(Whois::Record.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")]))
      expect(instance.expires_on?).to eq(false)
    end
  end

end
