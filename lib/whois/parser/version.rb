module Whois
  class Parser

    # Holds information about library version.
    module Version
      MAJOR = 1
      MINOR = 0
      PATCH = 0
      BUILD = nil

      STRING = [MAJOR, MINOR, PATCH, BUILD].compact.join(".")
    end

    # The current library version.
    VERSION = Version::STRING

  end
end
