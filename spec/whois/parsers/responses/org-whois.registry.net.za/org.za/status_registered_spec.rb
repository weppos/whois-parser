# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/org-whois.registry.net.za/org.za/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/org-whois.registry.net.za.rb'

describe Whois::Parsers::OrgWhoisRegistryNetZa, "status_registered.expected" do

  subject do
    file = fixture("responses", "org-whois.registry.net.za/org.za/status_registered.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#domain" do
    it do
      expect(subject.domain).to eq("joburg.org.za")
    end
  end
  describe "#domain_id" do
    it do
      expect(subject.domain_id).to eq("dom_8VP-9999")
    end
  end
  describe "#status" do
    it do
      expect(subject.status).to eq(:registered)
    end
  end
  describe "#available?" do
    it do
      expect(subject.available?).to eq(false)
    end
  end
  describe "#registered?" do
    it do
      expect(subject.registered?).to eq(true)
    end
  end
  describe "#created_on" do
    it do
      expect(subject.created_on).to be_a(Time)
      expect(subject.created_on).to eq(Time.parse("1997-10-03 09:46:34 UTC"))
    end
  end
  describe "#updated_on" do
    it do
      expect(subject.updated_on).to be_a(Time)
      expect(subject.updated_on).to eq(Time.parse("2015-02-05 08:45:51 UTC"))
    end
  end
  describe "#expires_on" do
    it do
      expect(subject.expires_on).to be_a(Time)
      expect(subject.expires_on).to eq(Time.parse("2999-12-31 21:59:59 UTC"))
    end
  end
  describe "#registrar" do
    it do
      expect(subject.registrar).to be_a(Whois::Parser::Registrar)
      expect(subject.registrar.id).to eq("9999")
      expect(subject.registrar.name).to eq("ZA Central Registry")
      expect(subject.registrar.organization).to eq("ZA Central Registry")
      expect(subject.registrar.url).to eq(nil)
    end
  end
  describe "#registrant_contacts" do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts.size).to eq(1)
      expect(subject.registrant_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.registrant_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_REGISTRANT)
      expect(subject.registrant_contacts[0].id).to eq("jobuRant")
      expect(subject.registrant_contacts[0].name).to eq("City of Johannesburg Metropolitan Municipality")
      expect(subject.registrant_contacts[0].organization).to eq("")
      expect(subject.registrant_contacts[0].address).to eq("P.O. Box 30757")
      expect(subject.registrant_contacts[0].city).to eq("Braamfontein")
      expect(subject.registrant_contacts[0].state).to eq("Gauteng")
      expect(subject.registrant_contacts[0].zip).to eq("2017")
      expect(subject.registrant_contacts[0].country).to eq(nil)
      expect(subject.registrant_contacts[0].country_code).to eq("ZA")
      expect(subject.registrant_contacts[0].phone).to eq("+27.110186314")
      expect(subject.registrant_contacts[0].fax).to eq("+27.113819583")
      expect(subject.registrant_contacts[0].email).to eq("joelsonp@joburg.org.za")
      expect(subject.registrant_contacts[0].created_on).to eq(nil)
      expect(subject.registrant_contacts[0].updated_on).to eq(nil)
    end
  end
  describe "#admin_contacts" do
    it do
      expect(subject.admin_contacts).to be_a(Array)
      expect(subject.admin_contacts.size).to eq(1)
      expect(subject.admin_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.admin_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_ADMINISTRATIVE)
      expect(subject.admin_contacts[0].id).to eq("zacr-a0c0379446")
      expect(subject.admin_contacts[0].name).to eq("Joelson Pholoha")
      expect(subject.admin_contacts[0].organization).to eq("")
      expect(subject.admin_contacts[0].address).to eq("Private Bag X10013, Sandton, 2146")
      expect(subject.admin_contacts[0].city).to eq("-")
      expect(subject.admin_contacts[0].zip).to eq("")
      expect(subject.admin_contacts[0].country).to eq(nil)
      expect(subject.admin_contacts[0].country_code).to eq("--")
      expect(subject.admin_contacts[0].phone).to eq("+27.110186314")
      expect(subject.admin_contacts[0].fax).to eq("+27.113819583")
      expect(subject.admin_contacts[0].email).to eq("Joelsonp@Joburg.org.za")
      expect(subject.admin_contacts[0].created_on).to eq(nil)
      expect(subject.admin_contacts[0].updated_on).to eq(nil)
    end
  end
  describe "#technical_contacts" do
    it do
      expect(subject.technical_contacts).to be_a(Array)
      expect(subject.technical_contacts.size).to eq(1)
      expect(subject.technical_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.technical_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_TECHNICAL)
      expect(subject.technical_contacts[0].id).to eq("zacr-71fff5bce2")
      expect(subject.technical_contacts[0].name).to eq("Eben Jacobs")
      expect(subject.technical_contacts[0].organization).to eq("")
      expect(subject.technical_contacts[0].address).to eq("Accounts Payable, Vida Building, Kabelweg 57, 1014 BA Amsterdam")
      expect(subject.technical_contacts[0].city).to eq("-")
      expect(subject.technical_contacts[0].zip).to eq("")
      expect(subject.technical_contacts[0].country).to eq(nil)
      expect(subject.technical_contacts[0].country_code).to eq("--")
      expect(subject.technical_contacts[0].phone).to eq("+27.110186314")
      expect(subject.technical_contacts[0].fax).to eq("+27.113819583")
      expect(subject.technical_contacts[0].email).to eq("ebenj@joburg.org.za")
      expect(subject.technical_contacts[0].created_on).to eq(nil)
      expect(subject.technical_contacts[0].updated_on).to eq(nil)
    end
  end
  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers.size).to eq(3)
      expect(subject.nameservers[0]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[0].name).to eq("demeter.is.co.za")
      expect(subject.nameservers[0].ipv4).to eq(nil)
      expect(subject.nameservers[0].ipv6).to eq(nil)
      expect(subject.nameservers[1]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[1].name).to eq("jupiter.is.co.za")
      expect(subject.nameservers[1].ipv4).to eq(nil)
      expect(subject.nameservers[1].ipv6).to eq(nil)
      expect(subject.nameservers[2]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[2].name).to eq("titan.is.co.za")
      expect(subject.nameservers[2].ipv4).to eq(nil)
      expect(subject.nameservers[2].ipv6).to eq(nil)
    end
  end
end
