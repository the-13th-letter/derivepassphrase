### Added

  - `derivepassphrase` now uses a central configuration file, and additional
    data files, some of which are service-specific.  (The `vault.json`
    configuration file is now rebranded as a data file.)  The configuration
    files are user-editable, the data files are `derivepassphrase`-editable.

    The configuration files are in TOML format, so installing
    `derivepassphrase` on Python 3.10 and older requires the [`tomli`][]
    package.

[tomli]: https://pypi.org/project/tomli/

### Changed

  - Unicode normalization settings for `vault` service names and stored
    passphrases are now stored in the central configuration file, instead of
    the `vault` data file.

