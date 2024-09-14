# Changelog for `derivepassphrase`

[![Keeping a changelog][CHANGELOG_BADGE]][KEEP_A_CHANGELOG]
[![Using Semantic Versioning][SEMVER_BADGE]][SEMANTIC_VERSIONING]

  [CHANGELOG_BADGE]: Keep_a_changelog-E05735.svg
  [SEMVER_BADGE]: SemVer-3F4551.svg
  [KEEP_A_CHANGELOG]: https://keepachangelog.com/en/1.1.0/ 'Keeping a changelog'
  [SEMANTIC_VERSIONING]: https://semver.org/ 'Using Semantic Versioning'

<aside markdown><small>
(All entries are from the perspective of a user, not a developer.
The <q>public API</q>, as defined by Semantic Versioning, is outlined in the
[Reference section][REFERENCE]: the set of documented modules, classes,
methods and functions, and the documented behavior, options and arguments of
the command-line tools.
As per the Semantic Versioning and the Keep a Changelog terminology,
<q>Fixed</q> entries justify a <q>patch</q> release,
<q>Added</q> and <q>Deprecated</q> entries a <q>minor</q> release,
and <q>Changed</q> and <q>Removed</q> entries a <q>major</q> release.
<q>Security</q> can justify any type of release;
if <q>major</q> or <q>minor</q>, these are accompanied by corresponding
entries of the respective types above.
Again as per Semantic Versioning, at major version zero, the above
justification is not yet binding, and <em>any</em> new release may
effectively constitute a new <q>major</q> release.)
</small></aside>

  [REFERENCE]: reference/index.md

<!-- towncrier release notes start -->

## 0.2.0 (2024-09-12)

#### Added

- Support configuration data export from `vault` in v0.2, v0.3 and storeroom
  formats.

    This feature requires the `cryptography` Python module, but is available
  even if `vault` is not installed. ([#1])

[#1]: https://github.com/the-13th-letter/derivepassphrase/1

#### Fixed

- Deploy versioned documentation with [mike](https://pypi.org/project/mike).
  Set up a "latest" tag and the "0.<var>x</var>" version of the documentation
  with the contents so far.

#### Changed

- Changed `sequin` and `ssh_agent_client` to be submodules of
  `derivepassphrase`.  Further moved `derivepassphrase.Vault` and
  `derivepassphrase.AmbiguousByteRepresentation` into a new submodule `vault`,
  and renamed submodule `ssh_agent_client` to `ssh_agent`. ([#3])
- Changed internal error handling and error messages, to better work in the
  context of a command-line tool. ([#4])
- Combine and consolidate `derivepassphrase.types` and
  `derivepassphrase.ssh_agent.types` into a new submodule
  `derivepassphrase._types`.  Despite the name, the module is public. ([#7])
- Warn the user when entering (directly, or via configuration
  editing/importing) a passphrase that is not in the configured Unicode
  normalization form. (But don't otherwise reject any textual master
  passphrases.) ([#9])
- Move all existing functionality into a subcommand, in anticipation of other
  passphrase derivation schemes, with different settings.  Automatically
  forward calls without a subcommand to the "vault" subcommand.

    Also store the settings in a file specific to the respective subsystem,
  instead of globally.  Automatically fall back to, and migrate, the old global
  settings file if no subsystem-specific configuration was found. ([#10])

- Make `derivepassphrase_export` a subcommand: `derivepassphrase export`.
  ([#11])

[#3]: https://github.com/the-13th-letter/derivepassphrase/3
[#4]: https://github.com/the-13th-letter/derivepassphrase/4
[#7]: https://github.com/the-13th-letter/derivepassphrase/7
[#9]: https://github.com/the-13th-letter/derivepassphrase/9
[#10]: https://github.com/the-13th-letter/derivepassphrase/10
[#11]: https://github.com/the-13th-letter/derivepassphrase/11

#### Deprecated

- Using the implied subcommand or the implied global configuration file is
  deprecated, and will be removed in v1.0.


## 0.1.3 (2024-07-28)

#### Fixed

- Do not crash upon selecting a key on the command-line if there already is a
  key stored in the configuration. ([#5])
- Create the configuration directory upon saving, if it does not yet exist.
  ([#6])
- Isolate the tests properly and consistently from the user's configuration, so
  that user configuration problems do not cause unrelated test failures. ([#8])
- Add an alternate MkDocs configuration for building the documentation in
  offline mode.
- Fix typing issues according to `mypy`'s strict mode.

[#5]: https://github.com/the-13th-letter/derivepassphrase/5
[#6]: https://github.com/the-13th-letter/derivepassphrase/6
[#8]: https://github.com/the-13th-letter/derivepassphrase/8


## 0.1.2 (2024-07-22)

#### Fixed

- Include and exclude the correct files in the `sdist` and `wheel`
  distributions.  (Previously, `sdist` contained VCS artifacts, and `wheel` was
  missing some paths.)
- Lint and reformat all code using [ruff](https://pypi.org/package/ruff/).
- Mention
  [`mkdocstrings-python`](https://pypi.org/package/mkdocstrings-python/) in
  the documentation's page footer.
- Remove JavaScript and external font loading from documentation website, so
  that the site works even in restricted browser settings.
- Set up a changelog, using [towncrier](https://pypi.org/package/towncrier).


## 0.1.1 (2024-07-14)

#### Fixed

- Restore the `__version__` attribute in all top-level packages.
- Declare compatibility with Python 3.10 in project metadata, and include
  necessary version-specific dependencies.
- Publish the documentation online, and link to it in the repository metadata
  and the Python package metadata.


## 0.1.0 (2024-07-14)

#### Added

- Initial release.
