### Added

  - `derivepassphrase` now includes basic support for localization: if the
    necessary translations are installed, then the diagnostics and help
    texts can be emitted in different languages.  Internally, this uses
    Python's standard [`gettext`][] system.

    (As of this version, no translations have actually been prepared yet.)

