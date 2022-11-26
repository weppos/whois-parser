# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.domain.com/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.domain.com.rb'

describe Whois::Parsers::WhoisDomainCom, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.domain.com/status_registered.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#domain" do
    it do
      expect(subject.domain).to eq("domain.com")
    end
  end
  describe "#domain_id" do
    it do
      expect(subject.domain_id).to eq("608082_DOMAIN_COM-VRSN")
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
      expect(subject.created_on).to eq(Time.parse("1994-07-01 04:00:00Z UTC"))
    end
  end
  describe "#updated_on" do
    it do
      expect(subject.updated_on).to be_a(Time)
      expect(subject.updated_on).to eq(Time.parse("2016-10-21 20:11:05 UTC"))
    end
  end
  describe "#expires_on" do
    it do
      expect(subject.expires_on).to be_a(Time)
      expect(subject.expires_on).to eq(Time.parse("2021-01-07 13:34:24 UTC"))
    end
  end
  describe "#registrar" do
    it do
      expect(subject.registrar).to be_a(Whois::Parser::Registrar)
      expect(subject.registrar.id).to eq("886")
      expect(subject.registrar.name).to eq("Domain.com, LLC")
      expect(subject.registrar.organization).to eq("Domain.com, LLC")
      expect(subject.registrar.url).to eq("www.domain.com")
    end
  end
  describe "#registrant_contacts" do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts.size).to eq(1)
      expect(subject.registrant_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.registrant_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_REGISTRANT)
      expect(subject.registrant_contacts[0].name).to eq("Domain Administrator")
      expect(subject.registrant_contacts[0].organization).to eq("Endurance International Group West, Inc")
      expect(subject.registrant_contacts[0].address).to eq("10 Corporate Drive Suite 300")
      expect(subject.registrant_contacts[0].city).to eq("Burlington")
      expect(subject.registrant_contacts[0].zip).to eq("01803")
      expect(subject.registrant_contacts[0].state).to eq("MA")
      expect(subject.registrant_contacts[0].country_code).to eq("US")
      expect(subject.registrant_contacts[0].phone).to eq("+1.3604495900")
      expect(subject.registrant_contacts[0].fax).to eq("+1.3602534234")
      expect(subject.registrant_contacts[0].email).to eq("corpdomains@endurance.com")
    end
  end
  describe "#admin_contacts" do
    it do
      expect(subject.admin_contacts).to be_a(Array)
      expect(subject.admin_contacts.size).to eq(1)
      expect(subject.admin_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.admin_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_ADMINISTRATIVE)
      expect(subject.admin_contacts[0].name).to eq("Domain Administrator")
      expect(subject.admin_contacts[0].organization).to eq("Endurance International Group West, Inc")
      expect(subject.admin_contacts[0].address).to eq("10 Corporate Drive Suite 300")
      expect(subject.admin_contacts[0].city).to eq("Burlington")
      expect(subject.admin_contacts[0].zip).to eq("01803")
      expect(subject.admin_contacts[0].state).to eq("MA")
      expect(subject.admin_contacts[0].country_code).to eq("US")
      expect(subject.admin_contacts[0].phone).to eq("+1.3604495900")
      expect(subject.admin_contacts[0].fax).to eq("+1.3602534234")
      expect(subject.admin_contacts[0].email).to eq("corpdomains@endurance.com")
    end
  end
  describe "#technical_contacts" do
    it do
      expect(subject.technical_contacts).to be_a(Array)
      expect(subject.technical_contacts.size).to eq(1)
      expect(subject.technical_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.technical_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_TECHNICAL)
      expect(subject.technical_contacts[0].name).to eq("Domain Administrator")
      expect(subject.technical_contacts[0].organization).to eq("Endurance International Group West, Inc")
      expect(subject.technical_contacts[0].address).to eq("10 Corporate Drive Suite 300")
      expect(subject.technical_contacts[0].city).to eq("Burlington")
      expect(subject.technical_contacts[0].zip).to eq("01803")
      expect(subject.technical_contacts[0].state).to eq("MA")
      expect(subject.technical_contacts[0].country_code).to eq("US")
      expect(subject.technical_contacts[0].phone).to eq("+1.3604495900")
      expect(subject.technical_contacts[0].fax).to eq("+1.3602534234")
      expect(subject.technical_contacts[0].email).to eq("corpdomains@endurance.com")
    end
  end
  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers.size).to eq(4)
      expect(subject.nameservers[0]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[0].name).to eq("ns-166.awsdns-20.com")
      expect(subject.nameservers[1]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[1].name).to eq("ns-683.awsdns-21.net")
      expect(subject.nameservers[2]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[2].name).to eq("ns-1250.awsdns-28.org")
      expect(subject.nameservers[3]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[3].name).to eq("ns-2022.awsdns-60.co.uk")
    end
  end
end
