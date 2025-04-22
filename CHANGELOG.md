# Changelog

This project uses [Semantic Versioning 2.0.0](http://semver.org/).


#### Release 2.0.0

- FIX: Updated parser for .RO tld
- FIX: Fixed support for all Donuts Inc. TLDs as they rebranded to Identity Digital Inc.
- FIX: Updated parser for .SO tld
- FIX: Updated parser for .CL tld
- FIX: Updated parser for .PT tld
- CHANGED: Adding ruby 3 to the test suite + updating jruby and remove it from the allowed failures
- FIX: Fixed .SO parser not loading correctly under jRuby
- NEW: Add support for ActiveSupport 7 + reduce ActiveSupport usage for Array.wap
- NEW: Added support for all (or fixing existing) CentralNic TLDs (136 at the time: .ADAC, .AE.ORG, .ALLFINANZ, .ART, .AUTO, .AUTOS, .BABY, .BAR, .BEAUTY, .BEST, .BH, .BLOG, .BMW, .BOATS, .BOND, .BOX, .BR.COM, .BUILD, .CAM, .CAR, .CARS, .CASE, .CEO, .CFD, .CN.COM, .CO.COM, .CO.NL, .CO.NO, .CO.RO, .COLLEGE, .COM.DE, .COM.SE, .COOP, .CYOU, .DE.COM, .DEALER, .DELOITTE, .DESI, .DESIGN, .DHL, .DVAG, .ETISALAT, .EU.COM, .FANS, .FEEDBACK, .FM, .FO, .FORUM, .FRESENIUS, .FRL, .FUN, .GAY, .GB.NET, .GD, .GENT, .GR.COM, .HAIR, .HOMES, .HOST, .HU.NET, .ICU, .IN.NET, .INC, .INK, .JP.NET, .JPN.COM, .KFH, .KPN, .KRED, .LIDL, .LONDON, .LOVE, .LPL, .LPLFINANCIAL, .LUXURY, .MAKEUP, .MEX.COM, .MINI, .MONSTER, .MOTORCYCLES, .MUSIC, .ONLINE, .OOO, .PID, .POHL, .PRESS, .PROTECTION, .PW, .QPON, .QUEST, .RADIO.AM, .REIT, .RENT, .REST, .RU.COM, .SA.COM, .SAARLAND, .SBS, .SCHWARZ, .SE.NET, .SECURITY, .SFR, .SHOP.RO, .SITE, .SKIN, .SMART, .SPACE, .STC, .STCGROUP, .STORAGE, .STORE, .TECH, .THEATRE, .TICKETS, .TUI, .UK.COM, .UK.NET, .UNO, .US.COM, .US.ORG, .VG, .VIVA, .WEBSITE, .WIKI, .WME, .موقع, .اتصالات, .البحرين, .بيتك, .VERMÖGENSBERATER, .VERMÖGENSBERATUNG, .XYZ, .YACHTS, .ZA.BZ, .ZA.COM, .ZUERICH)
- FIX: Updated parser for .IN tld which changed name
- FIX: Updated parser for .MX tld (and derivates: .COM.MX, .ORG.MX, etc.) which changed name
- FIX: Updated parser for .COM.AU tld (based on #100) Thanks @kovalevsky
- NEW: Added support for all DonutsInc TLDs (241 at the time: .ACADEMY, .ACCOUNTANTS, .ACTOR, .AGENCY, .AIRFORCE, .APARTMENTS, .ARMY, .ASSOCIATES, .ATTORNEY, .AUCTION, .BAND, .BARGAINS, .BIKE, .BINGO, .BOUTIQUE, .BUILDERS, .BUSINESS, .CAB, .CAFE, .CAMERA, .CAMP, .CAPITAL, .CARDS, .CARE, .CAREERS, .CASH, .CASINO, .CATERING, .CENTER, .CHARITY, .CHAT, .CHEAP, .CHURCH, .CITY, .CLAIMS, .CLEANING, .CLINIC, .CLOTHING, .COACH, .CODES, .COFFEE, .COMMUNITY, .COMPANY, .COMPUTER, .CONDOS, .CONSTRUCTION, .CONTACT, .CONTRACTORS, .COOL, .COUPONS, .CREDIT, .CREDITCARD, .CRUISES, .DANCE, .DATING, .DEALS, .DEGREE, .DELIVERY, .DEMOCRAT, .DENTAL, .DENTIST, .DIAMONDS, .DIGITAL, .DIRECT, .DIRECTORY, .DISCOUNT, .DOCTOR, .DOG, .DOMAINS, .EDUCATION, .EMAIL, .ENERGY, .ENGINEER, .ENGINEERING, .ENTERPRISES, .EQUIPMENT, .ESTATE, .EVENTS, .EXCHANGE, .EXPERT, .EXPOSED, .EXPRESS, .FAIL, .FAMILY, .FAN, .FARM, .FINANCE, .FINANCIAL, .FISH, .FITNESS, .FLIGHTS, .FLORIST, .FOOTBALL, .FORSALE, .FOUNDATION, .FUND, .FURNITURE, .FUTBOL, .FYI, .GALLERY, .GAMES, .GIFTS, .GIVES, .GLASS, .GMBH, .GOLD, .GOLF, .GRAPHICS, .GRATIS, .GRIPE, .GROUP, .GUIDE, .GURU, .HAUS, .HEALTHCARE, .HOCKEY, .HOLDINGS, .HOLIDAY, .HOSPITAL, .HOUSE, .IMMO, .IMMOBILIEN, .INDUSTRIES, .INSTITUTE, .INSURE, .INTERNATIONAL, .INVESTMENTS, .IRISH, .JETZT, .JEWELRY, .KAUFEN, .KITCHEN, .LAND, .LAWYER, .LEASE, .LEGAL, .LIFE, .LIGHTING, .LIMITED, .LIMO, .LIVE, .LOANS, .LTD, .MAISON, .MANAGEMENT, .MARKET, .MARKETING, .MBA, .MEDIA, .MEMORIAL, .MODA, .MONEY, .MORTGAGE, .MOVIE, .NAVY, .NETWORK, .NEWS, .NINJA, .PARTNERS, .PARTS, .PHOTOGRAPHY, .PHOTOS, .PICTURES, .PIZZA, .PLACE, .PLUMBING, .PLUS, .PRODUCTIONS, .PROPERTIES, .PUB, .RECIPES, .REHAB, .REISE, .REISEN, .RENTALS, .REPAIR, .REPORT, .REPUBLICAN, .RESTAURANT, .REVIEWS, .RIP, .ROCKS, .RUN, .SALE, .SALON, .SARL, .SCHOOL, .SCHULE, .SERVICES, .SHOES, .SHOPPING, .SHOW, .SINGLES, .SOCCER, .SOCIAL, .SOFTWARE, .SOLAR, .SOLUTIONS, .STUDIO, .STYLE, .SUPPLIES, .SUPPLY, .SUPPORT, .SURGERY, .SYSTEMS, .TAX, .TAXI, .TEAM, .TECHNOLOGY, .TENNIS, .THEATER, .TIENDA, .TIPS, .TIRES, .TODAY, .TOOLS, .TOURS, .TOWN, .TOYS, .TRAINING, .TRAVEL, .UNIVERSITY, .VACATIONS, .VENTURES, .VET, .VIAJES, .VIDEO, .VILLAS, .VIN, .VISION, .VOYAGE, .WATCH, .WINE, .WORKS, .WORLD, .WTF, .ZONE, .企业, .娱乐, .游戏, .商店)
- FIX: Updated parser for .CA tld
- NEW: Added parser for .WORLD tld
- NEW: Add whois.nic.google (support for .APP, .DEV, .HOW, .PAGE, .SOY) and update xn--q9jyb4c (.みんな) to use whois.nic.google (based on #124) Thanks @derekjc
- NEW: Added parser for .CLOUD tld
- FIX: Updated parser for .CO tld
- FIX: Updated parser for .FI tld (based on #133) Thanks @elguitar
- FIX: Fix throttled response detection for .CO.UK, .ME, .INFO, .MOBI (and most other Afilias based)
- CHANGED: Make sure times are parsed as UTC when no zone is specified (instead of using machine timezone) + improve parsing of some timezone when present and set japanese timezone.
- FIX: Big update and refactoring of all the Afilias based parser format, fixing broken parsing for .ME, .ORG, .INFO, .PRO, .BZ, .GI, .LC, .MN, .SC, .VC, .AG, .IN, .AERO, .ASIA, .MOBI, .POST, .XXX. (based on #34) Thanks @raszi and @jarthod
- CHANGED: Standardize a bit more the Registar object by always filling the name first (instead of sometimes filling organisation instead and sometimes duplicate both). Only fill "organization" when it's a real different property provided by the whois server.
- FIX: AFNIC parsers date format to avoid returning negative dates (#119) Thanks @itghlu
- CHANGED: Updated .IN.UA parsers to the latest response. (#69, #135) Thanks @Vanav and @jarthod
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
