# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.audns.net.au/au/property_status_with_multiple.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.audns.net.au.rb'

describe Whois::Parsers::WhoisAudnsNetAu, "property_status_with_multiple.expected" do

  subject do
    file = fixture("responses", "whois.audns.net.au/au/property_status_with_multiple.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#status" do
    it do
      expect(subject.status).to eq(["serverHold (Expired)", "serverUpdateProhibited (Expired)"])
    end
  end
end
