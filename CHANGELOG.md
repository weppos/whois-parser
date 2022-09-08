# Changelog

This project uses [Semantic Versioning 2.0.0](http://semver.org/).


#### Release 2.0.0

- CHANGED: Minimum Ruby version 2.6

- FIXED: Addressed security issues with eval and YAML.load. Thanks Francis Beaudoin


#### Release 1.2.0

- CHANGED: Updated .ORG parser to the latest response (GH-98, GH-97). [Thanks @talarini]
- CHANGED: Updated .IO, .AC, .SH, .TM parsers to the latest response.
- CHANGED: Renamed WhoisDomainKg to WhoisKg (GH-48)


#### Release 1.1.0

- NEW: Added .FM parser (GH-74). [Thanks @thomas07vt]
- NEW: Added .BR parser contacts (GH-31). [Thanks @forain]

- CHANGED: Updated WhoisAi to WhoisNicAi.
- CHANGED: WhoizBiz to the new response (GH-73). [Thanks @thomas07vt]
- CHANGED: WhoizNicSt to the new response (GH-72). [Thanks @fturmel]
- CHANGED: WhoisRegistryNetZa to the new response (GH-43). [Thanks @sheldonh]

- FIXED: Bug where .EU domain property had double .eu suffix (GH-63).
- FIXED: Fix scanning issue with .ca when keys have no value (GH-36).


#### Release 1.0.1

- CHANGED: Updated GoDaddy parser to the new response (GH-60).
- CHANGED: Updated Donuts parser to the new response. It looks like Donuts is now more compliant with base ICANN parser.
- CHANGED: Updated Verisign parser to the new response (GH-57). [Thanks @phcyso]
- CHANGED: Updated .BR parser to the new response (GH-51). [Thanks @otaviojr]
- CHANGED: Add support for :expires_on to base_nic_fr (GH-54). [Thanks @yastupin]


#### Release 1.0

**1.0.0-beta2**

- NEW: Added whois.cdmon.com parser (GH-27). [Thanks @sfumanal]

- FIXED: Fix for Record#respond_to?(:available?) (GH-28, GH-29, GH-30). Thanks [@marcandre]

**1.0.0-beta1**

Initial import from the `whois` library.

- NEW: whois.dk-hostmaster.dk parser now recognizes throttled responses (whois/GH-382). [Thanks @troelskn]
- NEW: Safer time parsing (GH-18). [Thanks @davidcornu]
- NEW: Detect reserved .INFO domains (whois/GH-468).

- CHANGED: whois.audns.net.au removed the registrar ID field (GH-20, GH-21). Thanks [@afoster]
- CHANGED: Updated .JOBS from obswhois.verisign-grs.com to whois.nic.jobs (GH-23).
- CHANGED: Updated .PRO from whois.dotproregistry.net to whois.afilias.net (GH-24).
