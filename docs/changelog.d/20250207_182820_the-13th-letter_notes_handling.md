### Added

  - `derivepassphrase vault` now supports selecting the editor interface
    when editing notes via the `--modern-editor-interface` and
    `--vault-legacy-editor-interface` options.

  - `derivepassphrase vault` now supports printing the service notes before
    the passphrase, as an alternative, instead of always printing them
    *after* the passphrase.

  - The tests concerning `derivepassphrase vault` and `--notes` usage have
    been rewritten into [hypothesis][]-based tests where feasible.

[hypothesis]: https://pypi.org/project/hypothesis/

### Changed

  - `derivepassphrase vault` now correctly requires the `--config` option in
    addition to the `--notes` option to request that the service notes be
    edited, for compatibility with vault(1).  `notes` is now also a valid
    setting name for `--unset` to take.  Furthermore, editing the notes
    successfully in any way, including no-op edits, will register the
    service name as a known service to `derivepassphrase vault`, even if the
    settings are otherwise empty.  Finally, using plain `--notes` without
    `--config` has no effect, and issues a warning to that extent.

  - `derivepassphrase vault` by default now uses an editor interface that
    matches vault(1): the contents of the edited text file are used directly
    as the service notes, without interpretation.  Previously, we
    post-processed the text file to remove comments and our instruction
    texts, and interpreted an empty file as a request to abort the edit.
    These two editor interfaces ("legacy" and "modern") can be explicitly
    selected, and for the legacy interface, which is less resilient against
    data entry or usage errors, a backup copy of the old notes content is
    made.

### Fixed

  - `derivepassphrase vault` now also prints the service notes (if any) when
    deriving a service passphrase, just like vault(1) does.

