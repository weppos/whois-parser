# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.denic.de/de/response_error_55000000010.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.denic.de.rb'

describe Whois::Parsers::WhoisDenicDe, "response_error_55000000010.expected" do

  subject do
    file = fixture("responses", "whois.denic.de/de/response_error_55000000010.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#status" do
    it do
      expect(subject.status).to eq(:invalid)
    end
  end
  describe "#available?" do
    it do
      expect(subject.available?).to eq(false)
    end
  end
  describe "#registered?" do
    it do
      expect(subject.registered?).to eq(false)
    end
  end
end
