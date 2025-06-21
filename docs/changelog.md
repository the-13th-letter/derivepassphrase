# Changelog for `derivepassphrase`

[![Keeping a changelog][CHANGELOG_BADGE]][KEEP_A_CHANGELOG]
[![Using Semantic Versioning][SEMVER_BADGE]][SEMANTIC_VERSIONING]

  [CHANGELOG_BADGE]: Keep_a_changelog-E05735.svg
  [SEMVER_BADGE]: SemVer-3F4551.svg
  [KEEP_A_CHANGELOG]: https://keepachangelog.com/en/1.1.0/ 'Keeping a changelog'
  [SEMANTIC_VERSIONING]: https://semver.org/ 'Using Semantic Versioning'

??? info "Definition: the <q>public API</q> of `derivepassphrase`"

    The <dfn>public API</dfn>, as defined by Semantic Versioning, is
    outlined in the [Reference section][REFERENCE]: the set of documented
    modules, classes, attributes, methods, functions and function
    parameters, and the documented behavior, options and arguments of the
    command-line tools.

    Certain **exceptions to this rule** are explicitly and prominently
    marked as implementation details/not part of the public API.

??? info "Interpretation of the version number"

    The terminology <b>major</b>, <b>minor</b> and <b>patch</b> follows the
    Semantic Versioning and Keep a Changelog definitions.

      * For version numbers with major version zero, *any* new release may
        effectively constitute a new <b>major</b> release.
      * For version numbers with major version one or higher,
          * <b>Fixed</b> entries justify a <b>patch</b> release;
          * <b>Added</b> and <b>Deprecated</b> entries justify
            a <b>minor</b> release;
          * <b>Changed</b> and <b>Removed</b> entries justify a <b>major</b>
            release.
          * <b>Security</b> can justify any type of release; if <b>major</b>
            or <b>minor</b>, these are accompanied by corresponding entries
            of the respective types above.

!!! abstract inline end "Legend: symbols"

    <ul style="list-style-type: none;">
    <li>:material-bug: --- a related bug entry from the wishlist page
    <li>:material-file-document-plus-outline: --- a related wishlist entry from the wishlist page
    </ul>

<aside markdown><small>
(All entries are from the perspective of a user of the program or the API.
As an exception, entries partaining to developers of `derivepassphrase` are
specifically marked as such.)
</small></aside>

<!-- scriv changelog start -->

## 0.5 (2025-06-14)  {#v0.5}

### Removed  {#removed-in-v0.5}

  - For [`derivepassphrase`][CLI], remove [support for (automatic) colored
    output or output with embedded text styling, as introduced in
    v0.4.0](#added-in-v0.4.0-color-support).

    This is a stopgap measure.
    There exist pseudo-standards (the `NO_COLOR` and `FORCE_COLOR`
    environment variables) governing how to influence this automatic
    detection, but they are under-specified with regard to their interaction
    with each other.
    Until a consensus is reached and automatic colored/styled output can be
    requested or rejected reliably across different terminal programs, we
    will rather emit only uncolored, unstyled, lowest-common-denominator
    device-independent output.
    →[:material-file-document-plus-outline:][WISH_CONVENTIONAL_CONFIGURABLE_TEXT_STYLING]

### Added  {#added-in-v0.5}

  - For the [`Vault`][derivepassphrase.vault.Vault] API, support reporting
    on whether two master passphrases are interchangable with respect to the
    service passphrases they can derive.
    This is an artefact of how the master passphrase is converted to the
    random bit sequence with which the service passphrases are generated.
    See the corresponding [FAQ entry: What are "interchangable passphrases"
    in vault?][INTERCHANGABLE_PASSPHRASES] for details, including the
    practical security (non-)implications.

    The [`derivepassphrase vault`][CLI_VAULT] command-line interface does
    not address this in any manner, mostly because the "non-standard"
    interchangable variants of a given master password tend to be ugly to
    type in, and because they do not have practical security implications.

  - For the [`Vault`][derivepassphrase.vault.Vault] API, accept arbitrary
    [Buffer][collections.abc.Buffer] objects as passphrases or service
    names, beyond [`bytes`][] and [`bytearray`][].

  - Expose [the vault UUID][derivepassphrase.vault.Vault.UUID] and [the
    character sets][derivepassphrase.vault.Vault.CHARSETS] as public
    attributes.

  - For [`derivepassphrase vault`][CLI_VAULT], support selecting the [editor
    interface](#changed-in-v0.5-editor-interface) when editing notes via the
    `--modern-editor-interface` and `--vault-legacy-editor-interface`
    options.

  - For [`derivepassphrase vault`][CLI_VAULT], support printing the service
    notes before the passphrase, as an alternative, instead of always
    printing them *after* the passphrase.
    →[:material-file-document-plus-outline:][WISH_PRINT_SERVICE_NOTES_ABOVE]

  - In the `--version` option of [`derivepassphrase`][CLI] and each
    subcommand, additionally report build and environment information, such
    as supported subcommands, derivation schemes, foreign configuration
    formats and active [PEP 508 extras](https://peps.python.org/pep-0508/).
    (Each subcommand only reports the items relevant to that subcommand.)
    →[:material-file-document-plus-outline:][WISH_REPORT_BUILD_FLAGS_AND_FEATURES]

  - For developers: Rewrite the tests concerning [`derivepassphrase
    vault`][CLI_VAULT] and `--notes` usage into [hypothesis][]-based tests
    where feasible.

  - For developers: Add scripts to the source tree to ensure consistent code
    quality: automatic linting, formatting and type checking, and optional
    running of the test suite and building of the documentation.
    The master quality control script doubles as a servicable (but
    heavyweight) "pre-commit" hook for git.

### Changed  {#changed-in-v0.5}

  - Support a new, unified interface
    [`ExportVaultConfigDataFunction`][derivepassphrase.exporter.ExportVaultConfigDataFunction]
    in the export handlers for "storeroom" and "vault-native" configuration
    data,
    [`export_storeroom_data`][derivepassphrase.exporter.storeroom.export_storeroom_data]
    and
    [`export_vault_native_data`][derivepassphrase.exporter.vault_native.export_vault_native_data].
    A new dispatch function
    [`export_vault_config_data`][derivepassphrase.exporter.export_vault_config_data]
    automatically calls the correct backend, based on the requested format.

    This is a **breaking API change** due to the change in function
    parameter names and return types.

  - Convert `KeyCommentPair` from [`derivepassphrase._types`][], and
    `KeyPair` and `MasterKeys` from
    [`derivepassphrase.exporter.storeroom`][], to
    [`NamedTuple`s][typing.NamedTuple]. Also rename them to
    [`SSHKeyCommentPair`][derivepassphrase._types.SSHKeyCommentPair],
    [`StoreroomKeyPair`][derivepassphrase._types.StoreroomKeyPair] and
    [`StoreroomMasterKeys`][derivepassphrase._types.StoreroomMasterKeys],
    respectively, in the [`derivepassphrase._types`][] module.

    This is a **breaking API change**.

  - Move the non-essential content of the [`derivepassphrase.cli`][] module
    into the "internals" subpackage.

    This is a **breaking API change** due to the removal of most functions
    from the [`derivepassphrase.cli`][] module.

  - For [`derivepassphrase vault`][CLI_VAULT], change the handling of the
    notes for better compatibility with <i>vault</i>(1) and for better
    internal consistency:

    1.  Correctly require the `--config` option in addition to the `--notes`
        option to request that the service notes be edited, for
        compatibility with <i>vault</i>(1).
        Issue a warning if `--notes` is used without `--config`.

    2.  `notes` is now also a valid setting name for `--unset` to take.

    3.  Editing the notes successfully in any way, including no-op edits,
        will register the service name as a known service to
        [`derivepassphrase vault`][CLI_VAULT], even if the settings are
        otherwise empty.

  - For [`derivepassphrase vault`][CLI_VAULT], by default, use an <b
    id="changed-in-v0.5-editor-interface">editor interface</b> that matches
    <i>vault</i>(1): the contents of the edited text file are used directly
    as the service notes, without interpretation.

    Previously, we post-processed the text file to remove comments and our
    instruction texts, and interpreted an empty file as a request to abort
    the edit.
    These two editor interfaces ("legacy" and "modern") can be explicitly
    selected, and for the legacy interface, which is less resilient against
    data entry or usage errors, a backup copy of the old notes content is
    made.

  - For developers: Use a different feature matrix and different
    [hypothesis][] profiles in the test suite.
    The slowdown caused by coverage measurement is now more accurately
    estimated and adjusted for in the [hypothesis][] settings.

  - For developers: Clean up, partly reorganize, and document the test
    suite, at least rudimentarily.
    Also add several new [hypothesis][]-based tests, particularly to test
    the core assumptions of the [vault][derivepassphrase.vault] derivation
    scheme about sensitivity (or lack thereof) to its inputs and its input
    formats.

  - For developers: For [`derivepassphrase vault`][CLI_VAULT], store our
    `vault.json` data file in pretty-printed form.
    This is a stopgap measure to ease debugging and introspection until
    better built-in query functionality for the effective configuration is
    available, because users should not be rewarded for meddling around in
    data files.
    →[:material-file-document-plus-outline:][WISH_PRETTY_PRINT_JSON]

### Fixed  {#fixed-in-v0.5}

  - Fix the misbehaving shell completion for `zsh` in the presence of colons
    in the completion item.
    This was due to an overzealous workaround for
    [`pallets/click#2703`](https://github.com/pallets/click/issues/2703).

  - For [`derivepassphrase vault`][CLI_VAULT], when exporting a vault
    configuration, export a pretty-printed configuration, to ease debugging
    and introspection.
    →[:material-file-document-plus-outline:][WISH_PRETTY_PRINT_JSON]

  - For [`derivepassphrase vault`][CLI_VAULT], also print the service notes
    (if any) when deriving a service passphrase, just like <i>vault</i>(1)
    does.
    →[:material-bug:][BUG_PRINT_SERVICE_NOTES]

  - Lock our internals and their configuration against concurrent
    modifications.
    →[:material-bug:][BUG_CONCURRENCY_AUDIT]

  - Test against PyPy 3.11.

  - Test on <abbr title="Microsoft Windows">The Annoying
    OS</abbr>[^the-annoying-os] in its baseline version, i.e., without SSH
    agent functionality but with `cryptography` support.
    Fix all incompatibilities in the test suite if essential and/or
    feasible, otherwise document them as skips or expected failures.

    (The latter case currently only concerns one single test that is
    supposed to trigger OS errors while attempting to read the
    `derivepassphrase` configuration files.
    <abbr title="Microsoft Windows">The Annoying OS</abbr> happily returns
    an empty file instead.)

  - For developers: Include build machinery to ensure consistency of our
    version number and our diagnostic messages between the documentation and
    the code, instead of having to check this by hand.

    (The canonical way to get the version number is the
    [`importlib.metadata.version`][] standard library interface.)

  - For developers: Test our locking implementation for correctness, on both
    sides of the API.
    Specifically, test that the respective platform-specific locking
    primitives provide the requested mutual exclusion properties, and that
    the locking system as a whole, when given functioning locking
    primitives, correctly serializes access to the facilities it is supposed
    to guard.
    →[:material-bug:][BUG_CONCURRENCY_TESTING_IN_TEST_SUITE]

## 0.4.0 (2025-01-07)  {#v0.4.0}

### Added  {#added-in-v0.4.0}

  - For [`derivepassphrase vault`][CLI_VAULT] and [`derivepassphrase export
    vault`][CLI_EXPORT_VAULT], support changing the amount of diagnostic
    output we emit via new command-line options `--debug`, `-v`/`--verbose`
    and `-q`/`--quiet`.
    Internally, we use Python's standard [logging][] and [warnings][]
    systems.

  - Use a central configuration file, and additional data files, some of
    which are service-specific.
    (The `vault.json` configuration file is now rebranded as a data file.)
    The configuration files are user-editable, the data files are
    [`derivepassphrase`][CLI]-editable.

    The configuration files are in TOML format, so installing
    `derivepassphrase` on Python 3.10 and older requires the
    [`tomli`][tomli] package.

  - For [`derivepassphrase vault --config`][CLI_VAULT], support an `--unset`
    option which unsets any given named setting prior to applying any other
    configuration changes.

  - For [`derivepassphrase vault --export`][CLI_VAULT], support exporting
    the current configuration as a POSIX `sh` script, using the
    `--export-as=sh` option.  The default (and previous behavior) is
    `--export-as=json`.

  - Include basic support for localization: if the necessary translations
    are installed, then the diagnostics and help texts can be emitted in
    different languages.
    Internally, we use Python's standard [`gettext`][] system.

    (As of this version, no translations have actually been prepared yet.)

  - For [`derivepassphrase`][CLI], explicitly support shell completion, in
    particular filename and service name completion in the [`export
    vault`][CLI_EXPORT_VAULT] and [`vault`][CLI_VAULT] subcommands.

    However, because of restrictions regarding the exchange of data between
    `derivepassphrase` and the shell, `derivepassphrase` will not offer any
    service names containing ASCII control characters for completion, and
    a warning will be issued when importing or configuring such a service.
    They may still otherwise be used normally.

  - <b id="added-in-v0.4.0-color-support">Support the semi-standard
    `NO_COLOR` and the `FORCE_COLOR` environment variables</b> to suppress
    or force color output from [`derivepassphrase`][CLI].  (`FORCE_COLOR`
    overrides `NO_COLOR` if both are set.)

### Changed  {#changed-in-v0.4.0}

  - Calling
    [`derivepassphrase_export`][derivepassphrase.cli.derivepassphrase_export],
    [`derivepassphrase_export_vault`][derivepassphrase.cli.derivepassphrase_export_vault]
    or
    [`derivepassphrase_vault`][derivepassphrase.cli.derivepassphrase_vault],
    or calling [`derivepassphrase`][derivepassphrase.cli.derivepassphrase]
    via its [`.main`][click.Command.main] method, causes those functions
    to use the standard Python [logging][] and [warnings][] facilities to
    issue diagnostic messages, without output to standard error.
    (This includes using [`click.testing.CliRunner`][], which uses `.main`
    calls under the hood.)
    Calling [`derivepassphrase`][derivepassphrase.cli.derivepassphrase]
    directly as a function diverts diagnostic messages to standard error.

  - Unicode normalization settings for `vault` service names and stored
    passphrases are now stored in the central configuration file, instead of
    the `vault` data file.

  - `derivepassphrase` changed its license from [MIT][] to [zlib/libpng][].
    This should only make a difference to people redistributing altered
    versions of `derivepassphrase`; the basic freedoms, and the
    combinability of `derivepassphrase` with other software should be
    unaffected.

[MIT]: https://spdx.org/licenses/MIT.html
[zlib/libpng]: https://spdx.org/licenses/Zlib.html

## 0.3.3 (2024-11-28)  {#v0.3.3}

### Added  {#added-in-v0.3.3}

  - Checking whether an SSH key is suitable now also depends on the SSH
    agent in use.
    API functions now optionally take an additional
    [`SSHAgentClient`][derivepassphrase.ssh_agent.SSHAgentClient] object to
    test agent-specific key suitability.
    If not given, then the old behavior is retained: SSH keys are suitable
    if they are suitable under any (conforming) SSH agent.

### Fixed  {#fixed-in-v0.3.3}

  - If the SSH agent supports deterministic DSA/ECDSA signatures (e.g.
    [RFC 6979][]), then mark DSA and ECDSA SSH keys as suitable.

[RFC 6979]: https://www.rfc-editor.org/rfc/rfc6979

## 0.3.2 (2024-10-21)  {#v0.3.2}

### Fixed  {#fixed-in-v0.3.2}

  - _*Actually* actually_ remove the `derivepassphrase_export` program,
    which was turned into a subcommand in v0.2.0 and supposed to have been
    removed in v0.3.1 already.
    Removed on disk is not the same as removed in version control.

## 0.3.1 (2024-10-21)  {#v0.3.1}

### Fixed  {#fixed-in-v0.3.1}

  - Fix PyPI classification: Python 3.9 is supported.
  - *Actually* remove the `derivepassphrase_export` program, which was
    turned into a subcommand in v0.2.0.

## 0.3.0 (2024-10-15)  {#v0.3.0}

### Added  {#added-in-v0.3.0}

  - Convert changelog management from towncrier to [scriv][].
  - Add SSH agent spawning support to the test suite.
    Use this support to test the agent functionality on all known major SSH
    agent implementations automatically.
    →[:material-file-document-plus-outline:][WISH_TEST_SUITE_ISOLATED_SSH_AGENT]
  - Add [hypothesis][]-based tests to the test suite.
  - Update README to add explanations for virtual environments and package
    extras.
  - Update README to demonstrate configuration storing and SSH agent use.
    Include comments on Windows support for SSH agents.
    →[:material-bug:][BUG_WINDOWS_SSH_AGENT_SUPPORT]
  - Use cross-references in the documentation of function signatures.
  - Add proper support for Buffer types in the SSH agent client.
    Any Python object supporting the buffer protocol can be used as input to
    a function of the client, and any output from the client is returned as
    bytes objects.
    Because of the zero-copy semantics of the underlying data/memory block,
    this should stay relatively time- and space-efficient.
  - Add [hypothesis][]-based tests for serialization to and
    deserialization from the SSH agent wire format.
  - Support Python 3.9 and 3.13.

### Changed  {#changed-in-v0.3.0}

  - Change links to point to public project repositories, if possible.
    For legal reasons.

  - Use the same filename/URL convention for API reference as the Python
    standard library does.

  - Rewrite functionality for checking for valid <i>vault</i>(1)
    configurations: include an actual validation function which throws
    errors upon encountering format violations, and which allows specifying
    which types of extensions (unknown settings, `derivepassphrase`-only
    settings) to tolerate during validation.

    This is a **breaking API change** because the function return annotation
    changed, from [`typing.TypeGuard`][] to [`typing_extensions.TypeIs`][].
    These were the originally intended semantics, but when
    `derivepassphrase` was first designed, the Python type system did not
    support this kind of partial type narrowing.

  - Fail earlier, and more gracefully/specifically, when we cannot talk to
    the SSH agent because Python does not support UNIX domain sockets on
    this system.
    In particular, this is the current situation on Windows.
    →[:material-bug:][BUG_FAIL_GRACEFULLY_WITHOUT_AF_UNIX]
    [:material-bug:][BUG_WINDOWS_SSH_AGENT_SUPPORT]

    This adds another failure case to the `SSHAgentClient` constructor, and
    therefore constitutes a **breaking API change**.

  - In [`derivepassphrase vault`][CLI_VAULT], accept `key` and `phrase`
    entries just like <i>vault</i>(1) does: `key` always overrides `phrase`
    in the configuration, no matter the level.

    This is a command-line only change.

  - In [`derivepassphrase vault`][CLI_VAULT], when importing settings,
    accept falsy values everywhere `vault` does, with a warning.
    Depending on the setting, they are equivalent to zero, the empty string,
    or "not set".
    →[:material-bug:][BUG_FALSY_VAULT_CONFIG_VALUES]

    This is a command-line only change, and only affects importing.
    The API provides a new function to normalize falsy settings, but still
    otherwise requires settings to be of the correct type.
    Storing a malformed configuration with such falsy values will still
    generate errors when [`derivepassphrase vault`][CLI_VAULT] loads the
    settings from disk.

  - In [`derivepassphrase vault`][CLI_VAULT], when importing configurations,
    correctly merge them with the existing one, same as <i>vault</i>(1):
    keep all named services and their settings (and the global settings if
    applicable) that are not mentioned in the imported configuration.
    The import procedure is thus more akin to a section-wise import of
    the configurations, instead of a "full" import, and the resulting
    configuration generally is a merge of both inputs.
    →[:material-bug:][BUG_AMEND_VAULT_CONFIG]

  - The following operations or configuration settings now raise
    warnings:

      * in imported configurations: using falsy values of the wrong type
      * in imported configurations: using falsy values with no practical
        effect
      * setting a passphrase in the configuration if a key is already
        set
      * using an empty service name on the command-line or in an
        imported configuration

### Fixed  {#fixed-in-v0.3.0}

  - Fixed the textual description of the return value for
    [`SSHAgentClient.request`][derivepassphrase.ssh_agent.SSHAgentClient.request],
    which didn't match the declared type annotation.

## 0.2.0 (2024-09-12)  {#v0.2.0}

### Added  {#added-in-v0.2.0}

  - Support configuration data export from `vault` in v0.2, v0.3 and
    storeroom formats.

    This feature requires the `cryptography` Python module, but is available
    even if `vault` is not installed.
    →[:material-file-document-plus-outline:][WISH_EXPORT_VAULT_FORMATS]

### Fixed  {#fixed-in-v0.2.0}

  - Deploy versioned documentation with [mike][].
    Set up a "latest" tag and the "0.<var>x</var>" version of the
    documentation with the contents so far.

### Changed  {#changed-in-v0.2.0}

  - Changed `sequin` and `ssh_agent_client` to be submodules of
    `derivepassphrase`.
    Further moved `derivepassphrase.Vault` and
    `derivepassphrase.AmbiguousByteRepresentation` into a new submodule
    `vault`, and renamed submodule `ssh_agent_client` to `ssh_agent`.
    →[:material-bug:][BUG_SINGLE_TOPLEVEL_MODULE]
  - Changed internal error handling and error messages, to better work in
    the context of a command-line tool.
    →[:material-bug:][BUG_BETTER_ERROR_MESSAGES]
  - Combine and consolidate `derivepassphrase.types` and
    `derivepassphrase.ssh_agent.types` into a new submodule
    `derivepassphrase._types`.
    Despite the name, the module is public.
    →[:material-bug:][BUG_NO_STDLIB_MODULE_NAMES]
  - Warn the user when entering (directly, or via configuration
    editing/importing) a passphrase that is not in the configured Unicode
    normalization form.
    (But don't otherwise reject any textual master passphrases.)
    →[:material-bug:][BUG_ALLOW_ALL_UNICODE_PASSPHRASES]
  - Move all existing functionality into a subcommand, in anticipation of
    other passphrase derivation schemes, with different settings.
    Automatically forward calls without a subcommand to the "vault"
    subcommand.

    Also store the settings in a file specific to the respective subsystem,
    instead of globally.
    Automatically fall back to, and migrate, the old global settings file if
    no subsystem-specific configuration was found.
    →[:material-file-document-plus-outline:][WISH_OTHER_DERIVATION_SCHEMES]
    [:material-file-document-plus-outline:][WISH_SCHEME_SPECIFIC_CLI_AND_CONFIG]

  - Make `derivepassphrase_export` a subcommand: [`derivepassphrase
    export`][CLI_EXPORT].
    →[:material-file-document-plus-outline:][WISH_EXPORTER_SCRIPT_AS_SUBCOMMAND]

### Deprecated  {#deprecated-in-v0.2.0}

  - Using the implied subcommand or the implied global settings file is
    deprecated, and will be removed in v1.0.


## 0.1.3 (2024-07-28)  {#v0.1.3}

### Fixed  {#fixed-in-v0.1.3}

  - Do not crash upon selecting a key on the command-line if there already
    is a key stored in the configuration.
    →[:material-bug:][BUG_ONE_TIME_KEY_OVERRIDE_FAILS]
  - Create the configuration directory upon saving, if it does not yet
    exist.
    →[:material-bug:][BUG_CONFIGURATION_DIRECTORY_MUST_EXIST]
  - Isolate the tests properly and consistently from the user's
    configuration, so that user configuration problems do not cause
    unrelated test failures.
    →[:material-bug:][BUG_TEST_FILESYSTEM_ISOLATION]
  - Add an alternate MkDocs configuration for building the documentation in
    offline mode.
  - Fix typing issues according to `mypy`'s strict mode.


## 0.1.2 (2024-07-22)  {#v0.1.2}

### Fixed  {#fixed-in-v0.1.2}

  - Include and exclude the correct files in the `sdist` and `wheel`
    distributions.
    (Previously, `sdist` contained VCS artifacts, and `wheel` was missing
    some paths.)
  - Lint and reformat all code using [ruff][].
  - Mention [`mkdocstrings-python`][mkdocstrings-python] in the
    documentation's page footer.
  - Remove JavaScript and external font loading from documentation website,
    so that the site works even in restricted browser settings.
  - Set up a changelog, using [towncrier][].


## 0.1.1 (2024-07-14)  {#v0.1.1}

### Fixed  {#fixed-in-v0.1.1}

  - Restore the `__version__` attribute in all top-level packages.
  - Declare compatibility with Python 3.10 in project metadata, and include
    necessary version-specific dependencies.
  - Publish the documentation online, and link to it in the repository
    metadata and the Python package metadata.


## 0.1.0 (2024-07-14)  {#v0.1.0}

### Added  {#added-in-v0.1.0}

  - Initial release.

[^the-annoying-os]: Hat tip---and apologies---to
    [Timothée Mazzucotelli (`@pawamoy`)](https://github.com/pawamoy/) for
    the fitting terminology.

[hypothesis]: https://pypi.org/project/hypothesis/
[mike]: https://pypi.org/project/mike/
[mkdocstrings-python]: https://pypi.org/project/mkdocstrings-python/
[ruff]: https://pypi.org/project/ruff/
[scriv]: https://pypi.org/project/scriv/
[tomli]: https://pypi.org/project/tomli/
[towncrier]: https://pypi.org/project/towncrier/

[CLI]: reference/derivepassphrase.1.md
[CLI_EXPORT]: reference/derivepassphrase-export.1.md
[CLI_EXPORT_VAULT]: reference/derivepassphrase-export-vault.1.md
[CLI_VAULT]: reference/derivepassphrase-vault.1.md
[INTERCHANGABLE_PASSPHRASES]: explanation/faq-vault-interchangable-passphrases.md
[REFERENCE]: reference/index.md

[BUG_ALLOW_ALL_UNICODE_PASSPHRASES]: wishlist/allow-all-unicode-passphrases.md "Bug entry: “Allow all Unicode text strings as master passphrases”"
[BUG_AMEND_VAULT_CONFIG]: wishlist/amend-vault-config.md "Bug entry: “derivepassphrase vault --import overwrites config instead of amending it”"
[BUG_BETTER_ERROR_MESSAGES]: wishlist/better-error-messages.md "Bug entry: “Improve common error messages in the command-line interface”"
[BUG_CONCURRENCY_AUDIT]: wishlist/concurrency-audit.md "Bug entry: “Audit derivepassphrase for concurrency/thread-safety issues”"
[BUG_CONCURRENCY_TESTING_IN_TEST_SUITE]: wishlist/concurrency-testing-in-test-suite.md "Bug entry: “Test for concurrency and assert thread-safety in derivepassphrase's test suite”"
[BUG_CONFIGURATION_DIRECTORY_MUST_EXIST]: wishlist/configuration-directory-must-exist.md "Bug entry: “derivepassphrase --config requires configuration directory to exist”"
[BUG_FAIL_GRACEFULLY_WITHOUT_AF_UNIX]: wishlist/fail-gracefully-without-af-unix.md "Bug entry: “Fail gracefully if support for UNIX domain sockets is unavailable”"
[BUG_FALSY_VAULT_CONFIG_VALUES]: wishlist/falsy-vault-config-values.md "Bug entry: “derivepassphrase vault differs from vault(1) behavior with falsy stored configuration values”"
[BUG_NO_STDLIB_MODULE_NAMES]: wishlist/no-stdlib-module-names.md "Bug entry: “Rename types submodules to _types”"
[BUG_ONE_TIME_KEY_OVERRIDE_FAILS]: wishlist/one-time-key-override-fails.md "Bug entry: “derivepassphrase -k fails when overriding the chosen key on the command-line”"
[BUG_PRINT_SERVICE_NOTES]: wishlist/print-service-notes.md "Bug entry: “derivepassphrase vault does not print service notes”"
[BUG_SINGLE_TOPLEVEL_MODULE]: wishlist/single-toplevel-module.md "Bug entry: “Move sequin and ssh_agent_client modules into derivepassphrase package”"
[BUG_TEST_FILESYSTEM_ISOLATION]: wishlist/test-filesystem-isolation.md "Bug entry: “Isolate tests properly from the filesystem”"
[BUG_WINDOWS_SSH_AGENT_SUPPORT]: wishlist/windows-ssh-agent-support.md "Bug entry: “Support PuTTY/Pageant (and maybe OpenSSH/ssh-agent) on Windows”"
[WISH_CONVENTIONAL_CONFIGURABLE_TEXT_STYLING]: wishlist/conventional-configurable-text-styling.md "Wish entry: “derivepassphrase vault should support conventional and configurable text styling”"
[WISH_EXPORTER_SCRIPT_AS_SUBCOMMAND]: wishlist/exporter-script-as-subcommand.md "Wish entry: “Make the exporter a subcommand of derivepassphrase”"
[WISH_EXPORT_VAULT_FORMATS]: wishlist/export-vault-formats.md "Wish entry: “Support data export from vault v0.2, vault v0.3, and storeroom storage formats”"
[WISH_OTHER_DERIVATION_SCHEMES]: wishlist/other-derivation-schemes.md "Wish entry: “Consider implementing passphrase schemes other than vault's”"
[WISH_PRETTY_PRINT_JSON]: wishlist/pretty-print-json.md "Wish entry: “derivepassphrase vault should store and export the vault configuration in pretty-printed JSON”"
[WISH_PRINT_SERVICE_NOTES_ABOVE]: wishlist/print-service-notes-above.md "Wish entry: “derivepassphrase vault should be able to print service notes above the passphrase”"
[WISH_REPORT_BUILD_FLAGS_AND_FEATURES]: wishlist/report-build-flags-and-features.md "Wish entry: “derivepassphrase should report its build flags and supported features”"
[WISH_SCHEME_SPECIFIC_CLI_AND_CONFIG]: wishlist/scheme-specific-cli-and-config.md "Wish entry: “Move vault-specific command-line interface into a separate CLI subcommand and matching configuration file”"
[WISH_TEST_SUITE_ISOLATED_SSH_AGENT]: wishlist/test-suite-isolated-ssh-agent.md "Wish entry: “Support and isolate OpenSSH's ssh-agent and PuTTY's pageant in the test suite”"
