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

<!-- scriv changelog start -->

## 0.3.3 (2024-11-28)

### Added

  - Checking whether an SSH key is suitable now also depends on the SSH
    agent in use.  API functions now optionally take an additional
    [`SSHAgentClient`][derivepassphrase.ssh_agent.SSHAgentClient] object to
    test agent-specific key suitability.  If not given, then the old
    behavior is retained: SSH keys are suitable if they are suitable under
    any (conforming) SSH agent.

### Fixed

  - If the SSH agent supports deterministic DSA/ECDSA signatures (e.g.
    [RFC 6979][]), then mark DSA and ECDSA SSH keys as suitable.

[RFC 6979]: https://www.rfc-editor.org/rfc/rfc6979

## 0.3.2 (2024-10-21)

### Fixed

  - _*Actually* actually_ remove the `derivepassphrase_export` program, which was
    turned into a subcommand in v0.2.0 and supposed to have been removed in
    v0.3.1 already.  Removed on disk is not the same as removed in
    version control.

## 0.3.1 (2024-10-21)

### Fixed

  - Fix PyPI classification: Python 3.9 is supported.
  - *Actually* remove the `derivepassphrase_export` program, which was
    turned into a subcommand in v0.2.0.

## 0.3.0 (2024-10-15)

### Added

  - Convert changelog management from towncrier to [scriv][].
  - Add SSH agent spawning support to the test suite.  Use this support to
    test the agent functionality on all known major SSH agent
    implementations automatically. ([#12])
  - Add [hypothesis][]-based tests to the test suite.
  - Update README to add explanations for virtual environments and package
    extras.
  - Update README to demonstrate configuration storing and SSH agent use.
    Include comments on Windows support for SSH agents.
  - Use cross-references in the documentation of function signatures.
  - Add proper support for Buffer types in the SSH agent client.  Any
    Python object supporting the buffer protocol can be used as input to
    a function of the client, and any output from the client is returned
    as bytes objects.  Because of the zero-copy semantics of the
    underlying data/memory block, this should stay relatively time- and
    space-efficient.
  - Add [hypothesis][]-based tests for serialization to and
    deserialization from the SSH agent wire format.
  - Support Python 3.9 and 3.13.

[#12]: https://github.com/the-13th-letter/derivepassphrase/issues/12
[hypothesis]: https://pypi.org/project/hypothesis/
[scriv]: https://pypi.org/project/scriv

### Changed

  - Change links to point to public project repositories, if possible.  For
    legal reasons.

  - Use the same filename/URL convention for API reference as the Python
    standard library does.

  - Rewrite functionality for checking for valid vault(1) configurations:
    include an actual validation function which throws errors upon
    encountering format violations, and which allows specifying which types
    of extensions (unknown settings, `derivepassphrase`-only settings) to
    tolerate during validation.

    This is a **breaking API change** because the function return annotation
    changed, from [`typing.TypeGuard`][] to [`typing_extensions.TypeIs`][].
    These were the originally intended semantics, but when
    `derivepassphrase` was first designed, the Python type system did not
    support this kind of partial type narrowing.

  - Fail earlier, and more gracefully/specifically, when we cannot talk to
    the SSH agent because Python does not support UNIX domain sockets on
    this system.  In particular, this is the current situation on Windows.

    This adds another failure case to the `SSHAgentClient` constructor, and
    therefore constitutes a **breaking API change**.

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

  - In `derivepassphrase vault`, when importing configurations,
    correctly merge them with the existing one, same as vault(1): keep
    all named services and their settings (and the global settings if
    applicable) that are not mentioned in the imported configuration.
    The import procedure is thus more akin to a section-wise import of
    the configurations, instead of a "full" import, and the resulting
    configuration generally is a merge of both inputs.  ([#16])

  - The following operations or configuration settings now raise
    warnings:

      * in imported configurations: using falsy values of the wrong type
      * in imported configurations: using falsy values with no practical
        effect
      * setting a passphrase in the configuration if a key is already
        set
      * using an empty service name on the command-line or in an
        imported configuration

[#16]: https://github.com/the-13th-letter/derivepassphrase/issues/16
[#17]: https://github.com/the-13th-letter/derivepassphrase/issues/17

### Fixed

  - Fixed the textual description of the return value for
    [`SSHAgentClient.request`][derivepassphrase.ssh_agent.SSHAgentClient.request],
    which didn't match the declared type annotation.

## 0.2.0 (2024-09-12)

### Added

  - Support configuration data export from `vault` in v0.2, v0.3 and
    storeroom formats.

    This feature requires the `cryptography` Python module, but is available
    even if `vault` is not installed. ([#1])

[#1]: https://github.com/the-13th-letter/derivepassphrase/1

### Fixed

  - Deploy versioned documentation with [mike][].  Set up a "latest" tag and
    the "0.<var>x</var>" version of the documentation with the contents so
    far.

[mike]: https://pypi.org/project/mike

### Changed

  - Changed `sequin` and `ssh_agent_client` to be submodules of
    `derivepassphrase`.  Further moved `derivepassphrase.Vault` and
    `derivepassphrase.AmbiguousByteRepresentation` into a new submodule
    `vault`, and renamed submodule `ssh_agent_client` to `ssh_agent`. ([#3])
  - Changed internal error handling and error messages, to better work in
    the context of a command-line tool. ([#4])
  - Combine and consolidate `derivepassphrase.types` and
    `derivepassphrase.ssh_agent.types` into a new submodule
    `derivepassphrase._types`.  Despite the name, the module is public.
    ([#7])
  - Warn the user when entering (directly, or via configuration
    editing/importing) a passphrase that is not in the configured Unicode
    normalization form. (But don't otherwise reject any textual master
    passphrases.) ([#9])
  - Move all existing functionality into a subcommand, in anticipation of
    other passphrase derivation schemes, with different settings.
    Automatically forward calls without a subcommand to the "vault"
    subcommand.

    Also store the settings in a file specific to the respective subsystem,
    instead of globally.  Automatically fall back to, and migrate, the old
    global settings file if no subsystem-specific configuration was found.
    ([#10])

  - Make `derivepassphrase_export` a subcommand: `derivepassphrase export`.
    ([#11])

[#3]: https://github.com/the-13th-letter/derivepassphrase/3
[#4]: https://github.com/the-13th-letter/derivepassphrase/4
[#7]: https://github.com/the-13th-letter/derivepassphrase/7
[#9]: https://github.com/the-13th-letter/derivepassphrase/9
[#10]: https://github.com/the-13th-letter/derivepassphrase/10
[#11]: https://github.com/the-13th-letter/derivepassphrase/11

### Deprecated

  - Using the implied subcommand or the implied global configuration file is
    deprecated, and will be removed in v1.0.


## 0.1.3 (2024-07-28)

### Fixed

  - Do not crash upon selecting a key on the command-line if there already
    is a key stored in the configuration. ([#5])
  - Create the configuration directory upon saving, if it does not yet
    exist.  ([#6])
  - Isolate the tests properly and consistently from the user's
    configuration, so that user configuration problems do not cause
    unrelated test failures. ([#8])
  - Add an alternate MkDocs configuration for building the documentation in
    offline mode.
  - Fix typing issues according to `mypy`'s strict mode.

[#5]: https://github.com/the-13th-letter/derivepassphrase/5
[#6]: https://github.com/the-13th-letter/derivepassphrase/6
[#8]: https://github.com/the-13th-letter/derivepassphrase/8


## 0.1.2 (2024-07-22)

### Fixed

  - Include and exclude the correct files in the `sdist` and `wheel`
    distributions.  (Previously, `sdist` contained VCS artifacts, and
    `wheel` was missing some paths.)
  - Lint and reformat all code using [ruff](https://pypi.org/package/ruff/).
  - Mention
    [`mkdocstrings-python`](https://pypi.org/package/mkdocstrings-python/)
    in the documentation's page footer.
  - Remove JavaScript and external font loading from documentation website,
    so that the site works even in restricted browser settings.
  - Set up a changelog, using
    [towncrier](https://pypi.org/package/towncrier).


## 0.1.1 (2024-07-14)

### Fixed

  - Restore the `__version__` attribute in all top-level packages.
  - Declare compatibility with Python 3.10 in project metadata, and include
    necessary version-specific dependencies.
  - Publish the documentation online, and link to it in the repository
    metadata and the Python package metadata.


## 0.1.0 (2024-07-14)

### Added

  - Initial release.
