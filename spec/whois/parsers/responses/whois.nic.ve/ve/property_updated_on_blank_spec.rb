# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.ve/ve/property_updated_on_blank.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.nic.ve.rb'

describe Whois::Parsers::WhoisNicVe, "property_updated_on_blank.expected" do

  subject do
    file = fixture("responses", "whois.nic.ve/ve/property_updated_on_blank.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#updated_on" do
    it do
      expect(subject.updated_on).to eq(nil)
    end
  end
end
