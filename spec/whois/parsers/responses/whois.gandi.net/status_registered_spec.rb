# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.gandi.net/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.gandi.net.rb'

describe Whois::Parsers::WhoisGandiNet, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.gandi.net/status_registered.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#domain" do
    it do
      expect(subject.domain).to eq("gandi.net")
    end
  end
  describe "#domain_id" do
    it do
      expect(subject.domain_id).to eq("6683836_DOMAIN_NET-VRSN")
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
      expect(subject.created_on).to eq(Time.parse("2000-02-23 12:12:59 UTC"))
    end
  end
  describe "#updated_on" do
    it do
      expect(subject.updated_on).to be_a(Time)
      expect(subject.updated_on).to eq(Time.parse("2013-10-23 18:42:52 UTC"))
    end
  end
  describe "#expires_on" do
    it do
      expect(subject.expires_on).to be_a(Time)
      expect(subject.expires_on).to eq(Time.parse("2023-05-21 14:09:56 UTC"))
    end
  end
  describe "#registrar" do
    it do
      expect(subject.registrar).to be_a(Whois::Parser::Registrar)
      expect(subject.registrar.id).to eq("81")
      expect(subject.registrar.name).to eq("GANDI SAS")
      expect(subject.registrar.organization).to eq("GANDI SAS")
      expect(subject.registrar.url).to eq("http://www.gandi.net")
    end
  end
  describe "#registrant_contacts" do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts.size).to eq(1)
      expect(subject.registrant_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.registrant_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_REGISTRANT)
      expect(subject.registrant_contacts[0].id).to eq(nil)
      expect(subject.registrant_contacts[0].name).to eq("Stephan RAMOIN")
      expect(subject.registrant_contacts[0].organization).to eq("Gandi SAS")
      expect(subject.registrant_contacts[0].address).to eq("63-65 Boulevard Massena")
      expect(subject.registrant_contacts[0].city).to eq("Paris")
      expect(subject.registrant_contacts[0].zip).to eq("75013")
      expect(subject.registrant_contacts[0].country).to eq(nil)
      expect(subject.registrant_contacts[0].country_code).to eq("FR")
      expect(subject.registrant_contacts[0].phone).to eq("+33.143737851")
      expect(subject.registrant_contacts[0].fax).to eq("+33.143731851")
      expect(subject.registrant_contacts[0].email).to eq("61ebd5b3df9f45f2b3f67f6dd01e1049-523678@contact.gandi.net")
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
      expect(subject.admin_contacts[0].id).to eq(nil)
      expect(subject.admin_contacts[0].name).to eq("Noc GANDI")
      expect(subject.admin_contacts[0].organization).to eq("GANDI SAS")
      expect(subject.admin_contacts[0].address).to eq("63-65 Boulevard MASSENA")
      expect(subject.admin_contacts[0].city).to eq("Paris")
      expect(subject.admin_contacts[0].zip).to eq("75013")
      expect(subject.admin_contacts[0].country).to eq(nil)
      expect(subject.admin_contacts[0].country_code).to eq("FR")
      expect(subject.admin_contacts[0].phone).to eq("+33.143737851")
      expect(subject.admin_contacts[0].fax).to eq("+33.143731851")
      expect(subject.admin_contacts[0].email).to eq("12e7da77f638acdf8d9f4d0b828ca80c-248842@contact.gandi.net")
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
      expect(subject.technical_contacts[0].id).to eq(nil)
      expect(subject.technical_contacts[0].name).to eq("Noc GANDI")
      expect(subject.technical_contacts[0].organization).to eq("GANDI SAS")
      expect(subject.technical_contacts[0].address).to eq("63-65 Boulevard MASSENA")
      expect(subject.technical_contacts[0].city).to eq("Paris")
      expect(subject.technical_contacts[0].zip).to eq("75013")
      expect(subject.technical_contacts[0].country).to eq(nil)
      expect(subject.technical_contacts[0].country_code).to eq("FR")
      expect(subject.technical_contacts[0].phone).to eq("+33.143737851")
      expect(subject.technical_contacts[0].fax).to eq("+33.143731851")
      expect(subject.technical_contacts[0].email).to eq("12e7da77f638acdf8d9f4d0b828ca80c-248842@contact.gandi.net")
      expect(subject.technical_contacts[0].created_on).to eq(nil)
      expect(subject.technical_contacts[0].updated_on).to eq(nil)
    end
  end
  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers.size).to eq(4)
      expect(subject.nameservers[0]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[0].name).to eq("dns0.gandi.net")
      expect(subject.nameservers[0].ipv4).to eq(nil)
      expect(subject.nameservers[0].ipv6).to eq(nil)
      expect(subject.nameservers[1]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[1].name).to eq("dns1.gandi.net")
      expect(subject.nameservers[1].ipv4).to eq(nil)
      expect(subject.nameservers[1].ipv6).to eq(nil)
      expect(subject.nameservers[2]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[2].name).to eq("dns2.gandi.net")
      expect(subject.nameservers[2].ipv4).to eq(nil)
      expect(subject.nameservers[2].ipv6).to eq(nil)
      expect(subject.nameservers[3]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[3].name).to eq("dns3.gandi.net")
      expect(subject.nameservers[3].ipv4).to eq(nil)
      expect(subject.nameservers[3].ipv6).to eq(nil)
    end
  end
end
