require 'spec_helper'
require 'whois/parsers/blank'

describe Whois::Parsers::Blank do

  let(:part) { Whois::Record::Part.new(body: "This is the response.", host: "whois.example.test") }

  Whois::Parser::PROPERTIES.each do |method|
    describe "##{method}" do
      it "raises Whois::ParserNotFound" do
        expect {
          described_class.new(part).send(method)
        }.to raise_error(Whois::ParserNotFound, /whois.example.test/)
      end
    end
  end

end
