# Changelog

This project uses [Semantic Versioning 2.0.0](http://semver.org/).


##### master

Initial import from the `whois` library.

- NEW: whois.dk-hostmaster.dk parser now recognizes throttled responses (whois/GH-382). [Thanks @troelskn]

- NEW: Safer time parsing (GH-18). [Thanks @davidcornu]

- NEW: Detect reserved .INFO domains (whois/GH-468).

- NEW: Added whois.cdmon.com parser (GH-27). [Thanks @sfumanal]

- FIXED: whois.audns.net.au removed the registrar ID field (GH-20, GH-21). Thanks [@afoster]

- CHANGED: Updated .JOBS from obswhois.verisign-grs.com to whois.nic.jobs (GH-23).

- CHANGED: Updated .PRO from whois.dotproregistry.net to whois.afilias.net (GH-24).
