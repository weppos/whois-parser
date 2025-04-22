# encoding: utf-8

require 'spec_helper'
require 'whois/parsers/whois.jprs.jp.rb'

describe Whois::Parsers::WhoisJprsJp, "property_registrar.expected" do

  subject do
    file = fixture("responses", "whois.jprs.jp/jp/property_registrar.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#registrar" do
    it do
      expect(subject.registrar).to be_a(Whois::Parser::Registrar)
      expect(subject.registrar.id).to eq(nil)
      expect(subject.registrar.name).to eq("Netowl,Inc.")
      expect(subject.registrar.organization).to eq("Netowl, Inc.")
      expect(subject.registrar.url).to eq(nil)
    end
  end

end 