# Changelog

This project uses [Semantic Versioning 2.0.0](http://semver.org/).


#### master

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
