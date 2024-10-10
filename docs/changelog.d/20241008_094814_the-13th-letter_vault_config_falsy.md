### Changed

  - In `derivepassphrase vault`, accept `key` and `phrase` entries just like
    vault(1) does: `key` always overrides `phrase` in the configuration, no
    matter the level.

    This is a command-line only change.

  - In `derivepassphrase vault`, when importing settings, accept falsy values
    everywhere `vault` does, with a warning.  Depending on the setting, they
    are equivalent to zero, the empty string, or "not set".  ([#17])

    This is a command-line only change, and only affects importing.  The API
    provides a new function to normalize falsy settings, but still otherwise
    requires settings to be of the correct type.  Storing a malformed
    configuration with such falsy values will still generate errors when
    `derivepassphrase vault` loads the settings from disk.

[#17]: https://github.com/the-13th-letter/derivepassphrase/issues/17
