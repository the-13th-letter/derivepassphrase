### Fixed

  - When exporting a vault configuration, `derivepassphrase vault` now
    exports a pretty-printed configuration, to ease debugging and
    introspection. ([#20])

### Changed

  - `derivepassphrase vault` stores its `vault.json` data file in
    pretty-printed form.  This is a stopgap measure to ease debugging and
    introspection until better built-in query functionality for the effective
    configuration is available, because users should not be rewarded. ([#20])

[#20]: https://github.com/the-13th-letter/derivepassphrase/issues/20
