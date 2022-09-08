require 'spec_helper'
require 'whois/parser_extensions'

describe Whois::Record do

  subject { described_class.new(server, parts) }

  let(:server) {
    Whois::Server.factory(:tld, ".foo", "whois.example.test")
  }
  let(:parts) {
    [
   Whois::Record::Part.new(body: "This is a record from foo.", host: "foo.example.test"),
   Whois::Record::Part.new(body: "This is a record from bar.", host: "bar.example.test"),
 ]
  }


  describe "#respond_to?" do
    before(:all) do
      @_properties  = Whois::Parser::PROPERTIES.dup
      @_methods     = Whois::Parser::METHODS.dup
    end

    after(:all) do
      Whois::Parser::PROPERTIES.replace(@_properties)
      Whois::Parser::METHODS.replace(@_methods)
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
      Whois::Parser::PROPERTIES << :test_property_b
      expect(subject.respond_to?(:test_property_b?)).to eq(true)
    end

    it "returns true if method? is a property?" do
      Whois::Parser::PROPERTIES << :test_property_c?
      expect(subject.respond_to?(:test_property_c?)).to eq(true)
    end

    it "returns true if method is a method" do
      Whois::Parser::METHODS << :test_method
      expect(subject.respond_to?(:test_method)).to eq(true)
    end

    it "returns true if method is a method?" do
      Whois::Parser::METHODS << :test_method_b
      expect(subject.respond_to?(:test_method_b?)).to eq(true)
    end

    it "returns true if method? is a method?" do
      Whois::Parser::METHODS << :test_method_c?
      expect(subject.respond_to?(:test_method_c?)).to eq(true)
    end
  end

  describe "#method" do
    before(:all) do
      @_properties  = Whois::Parser::PROPERTIES.dup
      @_methods     = Whois::Parser::METHODS.dup
    end

    after(:all) do
      Whois::Parser::PROPERTIES.replace(@_properties)
      Whois::Parser::METHODS.replace(@_methods)
    end

    it "returns true if method is in self" do
      expect(subject.method(:to_s)).to be_instance_of Method
    end

    it "returns true if method is in hierarchy" do
      expect(subject.method(:nil?)).to be_instance_of Method
    end

    it "returns true if method is a property" do
      Whois::Parser::PROPERTIES << :test_md_property
      expect(subject.method(:test_md_property)).to be_instance_of Method
    end

    it "returns true if method is a property?" do
      Whois::Parser::PROPERTIES << :test_md_property_b
      expect(subject.method(:test_md_property_b?)).to be_instance_of Method
    end

    it "returns true if method? is a property?" do
      Whois::Parser::PROPERTIES << :test_md_property_c?
      expect(subject.method(:test_md_property_c?)).to be_instance_of Method
    end

    it "returns true if method is a method" do
      Whois::Parser::METHODS << :test_md_method
      expect(subject.method(:test_md_method)).to be_instance_of Method
    end

    it "returns true if method is a method?" do
      Whois::Parser::METHODS << :test_md_method_b
      expect(subject.method(:test_md_method_b?)).to be_instance_of Method
    end

    it "returns true if method? is a method?" do
      Whois::Parser::METHODS << :test_md_method_c?
      expect(subject.method(:test_md_method_c?)).to be_instance_of Method
    end
  end

  # describe "#properties", skip: "Handle NotImplemented, NotSupported" do
  #   it "returns a Hash" do
  #     expect(subject.properties).to be_a(Hash)
  #   end
  #
  #   it "returns both nil and not-nil values" do
  #     expect(subject).to receive(:domain).and_return("")
  #     expect(subject).to receive(:created_on).and_return(nil)
  #     expect(subject).to receive(:expires_on).and_return(Time.parse("2010-10-10"))
  #
  #     properties = subject.properties
  #     expect(properties[:domain]).to eq("")
  #     expect(properties[:created_on]).to be_nil
  #     expect(properties[:expires_on]).to eq(Time.parse("2010-10-10"))
  #   end
  #
  #   it "fetches all parser property" do
  #     expect(subject.properties.keys).to match(Whois::Parser::PROPERTIES)
  #   end
  # end


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
      instance = described_class.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")])
      expect(instance.created_on).to eq(Date.parse("2010-10-20"))
    end

    it "raises Whois::AttributeNotSupported when the property is not supported" do
      instance = described_class.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")])
      expect { instance.updated_on }.to raise_error(Whois::AttributeNotSupported)
    end

    it "raises Whois::AttributeNotImplemented when the property is not implemented" do
      instance = described_class.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")])
      expect { instance.expires_on }.to raise_error(Whois::AttributeNotImplemented)
    end
  end

  describe "property?" do
    it "returns true when the property is supported and has no value" do
      instance = described_class.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")])
      expect(instance.status?).to eq(false)
    end

    it "returns false when the property is supported and has a value" do
      instance = described_class.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")])
      expect(instance.created_on?).to eq(true)
    end

    it "raises Whois::AttributeNotSupported when the property is not supported" do
      instance = described_class.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")])
      expect { instance.updated_on? }.to raise_error(Whois::AttributeNotSupported)
    end

    it "raises Whois::AttributeNotImplemented when the property is not implemented" do
      instance = described_class.new(nil, [Whois::Record::Part.new(body: "", host: "whois.properties.test")])
      expect { instance.expires_on? }.to raise_error(Whois::AttributeNotImplemented)
    end
  end


  describe "#changed?" do
    it "raises if the argument is not an instance of the same class" do
      expect {
        described_class.new(nil, []).changed?(Object.new)
      }.to raise_error(ArgumentError)

      expect {
        described_class.new(nil, []).changed?(described_class.new(nil, []))
      }.not_to raise_error
    end
  end

  describe "#unchanged?" do
    it "raises if the argument is not an instance of the same class" do
      expect {
        described_class.new(nil, []).unchanged?(Object.new)
      }.to raise_error(ArgumentError)

      expect {
        described_class.new(nil, []).unchanged?(described_class.new(nil, []))
      }.not_to raise_error
    end

    it "returns true if self and other references the same object" do
      instance = described_class.new(nil, [])
      expect(instance.unchanged?(instance)).to eq(true)
    end

    it "delegates to #parser if self and other references different objects" do
      other = described_class.new(nil, parts)
      instance = described_class.new(nil, parts)
      expect(instance.parser).to receive(:unchanged?).with(other.parser)

      instance.unchanged?(other)
    end
  end

  describe "#contacts" do
    it "delegates to parser" do
      expect(subject.parser).to receive(:contacts).and_return([:one, :two])
      expect(subject.contacts).to eq([:one, :two])
    end
  end


  describe "#response_incomplete?" do
    it "delegates to #parser" do
      expect(subject.parser).to receive(:response_incomplete?)
      subject.response_incomplete?
    end
  end

  describe "#response_throttled?" do
    it "delegates to #parser" do
      expect(subject.parser).to receive(:response_throttled?)
      subject.response_throttled?
    end
  end

  describe "#response_unavailable?" do
    it "delegates to #parser" do
      expect(subject.parser).to receive(:response_unavailable?)
      subject.response_unavailable?
    end
  end


  describe "method_missing" do
    context "when a parser property"
    context "when a parser method"

    context "when a parser question method/property" do
      it "calls the corresponding no-question method" do
        expect(subject).to receive(:status)
        subject.status?
      end

      it "returns true if the property is not nil" do
        expect(subject).to receive(:status).and_return("available")
        expect(subject.status?).to eq(true)
      end

      it "returns false if the property is nil" do
        expect(subject).to receive(:status).and_return(nil)
        expect(subject.status?).to eq(false)
      end
    end

    context "when a simple method" do
      it "passes the request to super" do
        Object.class_eval do
          def happy
            "yes"
          end
        end

        record = described_class.new(nil, [])
        expect {
          expect(record.happy).to eq("yes")
        }.not_to raise_error
        expect {
          record.sad
        }.to raise_error(NoMethodError)
      end

      it "does not catch all methods" do
        expect {
          described_class.new(nil, []).i_am_not_defined
        }.to raise_error(NoMethodError)
      end

      it "does not catch all question methods" do
        expect {
          described_class.new(nil, []).i_am_not_defined?
        }.to raise_error(NoMethodError)
      end
    end
  end

end
