require 'spec_helper'

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

  describe "#parser" do
    it "returns a Parser" do
      expect(subject.parser).to be_a(Whois::Parser)
    end

    it "initializes the parser with self" do
      expect(subject.parser.record).to be(subject)
    end

    it "memoizes the value" do
      expect(subject.instance_eval { @parser }).to be_nil
      parser = subject.parser
      expect(subject.instance_eval { @parser }).to be(parser)
    end
  end

end
