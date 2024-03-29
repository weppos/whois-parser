# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.uk/uk/property_registrar_godaddy.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.nic.uk.rb'

describe Whois::Parsers::WhoisNicUk, "property_registrar_godaddy.expected" do

  subject do
    file = fixture("responses", "whois.nic.uk/uk/property_registrar_godaddy.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#registrar" do
    it do
      expect(subject.registrar).to be_a(Whois::Parser::Registrar)
      expect(subject.registrar.id).to eq("GODADDY")
      expect(subject.registrar.name).to eq("GoDaddy.com, LLP.")
      expect(subject.registrar.name).to eq("GoDaddy.com, LLP.")
      expect(subject.registrar.url).to eq(nil)
    end
  end
end
