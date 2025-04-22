⚠️ WARNING: this repository is a fork of https://github.com/weppos/whois-parser. I created it because the maintainer seems [to have paused](https://github.com/weppos/whois-parser/pull/135) so the project was lagging more and more behind actual WHOIS definitions and the [PR piling up](https://github.com/weppos/whois-parser/pulls). I hope we'll be able to merge this back into the main project eventually but in the meantime if you need a more up-to-date and maintained version you can use this one:

Gemfile:
```ruby
gem 'whois-parser', github: 'jarthod/whois-parser' # Unofficial but more up-to-date fork, check status at https://github.com/jarthod/whois-parser
```

I'll try to merge as much existing PR as possible into this fork and provide my own updates too. I don't want to release the gem under another name at the moment to make it easier to go back to the official gem if possible, if so I'll update this page so you can check it from time to time when you see this comment in your Gemfile. The [CHANGELOG](CHANGELOG.md) file will be updated with all the changes in this fork, you can compare it with the upstream [CHANGELOG](https://github.com/weppos/whois-parser/blob/master/CHANGELOG.md)

Below is the unmodified upstream Readme to make merging easier.

---

# [Whois](https://whoisrb.org/) Parser

<tt>Whois Parser</tt> is a — pure Ruby — WHOIS parser.

This library was extracted from the Ruby <tt>Whois</tt> library], and made available as a standalone library. It can be used in combination with the Ruby Whois library to perform WHOIS queries and parse the response in Ruby, or as a standalone library to parse WHOIS records fetched previously and/or from different WHOIS clients.

[![Build Status](https://github.com/weppos/whois-parser/actions/workflows/tests.yml/badge.svg)](https://github.com/weppos/whois/actions/workflows/tests.yml)

The [whois repository](https://github.com/weppos/whois) contains more information on how to use the library.


## More Information

- [Homepage](https://whoisrb.org/)
- RubyGems: [`whois`](https://rubygems.org/gems/whois) and [`whois-parser`](https://rubygems.org/gems/whois-parser)
- Issues: [`whois`](https://github.com/weppos/whois) and [`whois-parser`](https://github.com/weppos/whois-parser)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/whois-ruby)


## Versioning

<tt>Whois::Parser</tt> uses [Semantic Versioning 2.0.0](http://semver.org)


## License

Copyright (c) 2009-2022 [Simone Carletti](https://simonecarletti.com/). This is Free Software distributed under the MIT license.
