# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Tests for the `derivepassphrase` command-line interface: all subcommands.

This includes tests for functionality or options common to all
subcommands.

"""

from __future__ import annotations

import contextlib
import enum
import re
import types

import exceptiongroup
import pytest
from typing_extensions import NamedTuple

from derivepassphrase import _types, cli, ssh_agent
from derivepassphrase._internals import cli_messages
from tests import machinery
from tests.machinery import pytest as pytest_machinery


class VersionOutputData(NamedTuple):
    derivation_schemes: dict[str, bool]
    foreign_configuration_formats: dict[str, bool]
    extras: frozenset[str]
    subcommands: frozenset[str]
    features: dict[str, bool]


def _label_text(e: cli_messages.Label, /) -> str:
    return e.value.singular.rstrip(":")


class KnownLineType(str, enum.Enum):
    SUPPORTED_FOREIGN_CONFS = _label_text(
        cli_messages.Label.SUPPORTED_FOREIGN_CONFIGURATION_FORMATS
    )
    UNAVAILABLE_FOREIGN_CONFS = _label_text(
        cli_messages.Label.UNAVAILABLE_FOREIGN_CONFIGURATION_FORMATS
    )
    SUPPORTED_SCHEMES = _label_text(
        cli_messages.Label.SUPPORTED_DERIVATION_SCHEMES
    )
    UNAVAILABLE_SCHEMES = _label_text(
        cli_messages.Label.UNAVAILABLE_DERIVATION_SCHEMES
    )
    SUPPORTED_SUBCOMMANDS = _label_text(
        cli_messages.Label.SUPPORTED_SUBCOMMANDS
    )
    SUPPORTED_FEATURES = _label_text(cli_messages.Label.SUPPORTED_FEATURES)
    UNAVAILABLE_FEATURES = _label_text(cli_messages.Label.UNAVAILABLE_FEATURES)
    ENABLED_EXTRAS = _label_text(cli_messages.Label.ENABLED_PEP508_EXTRAS)


class Parametrize(types.SimpleNamespace):
    """Common test parametrizations."""

    EAGER_ARGUMENTS = pytest.mark.parametrize(
        "arguments",
        [["--help"], ["--version"]],
        ids=["help", "version"],
    )
    COMMAND_NON_EAGER_ARGUMENTS = pytest.mark.parametrize(
        ["command", "non_eager_arguments"],
        [
            pytest.param(
                [],
                [],
                id="top-nothing",
            ),
            pytest.param(
                [],
                ["export"],
                id="top-export",
            ),
            pytest.param(
                ["export"],
                [],
                id="export-nothing",
            ),
            pytest.param(
                ["export"],
                ["vault"],
                id="export-vault",
            ),
            pytest.param(
                ["export", "vault"],
                [],
                id="export-vault-nothing",
            ),
            pytest.param(
                ["export", "vault"],
                ["--format", "this-format-doesnt-exist"],
                id="export-vault-args",
            ),
            pytest.param(
                ["vault"],
                [],
                id="vault-nothing",
            ),
            pytest.param(
                ["vault"],
                ["--export", "./"],
                id="vault-args",
            ),
        ],
    )
    HELP_OUTPUT_COMMAND_LINE = pytest.mark.parametrize(
        ["command_line", "expected_lines"],
        [
            pytest.param(
                [],
                ["currently implemented subcommands"],
                id="derivepassphrase",
            ),
            pytest.param(
                ["export"],
                ["only available subcommand"],
                id="derivepassphrase-export",
            ),
            pytest.param(
                ["export", "vault"],
                ["Export a vault-native configuration"],
                id="derivepassphrase-export-vault",
            ),
            pytest.param(
                ["vault"],
                [
                    "Passphrase generation:",
                    "Use $VISUAL or $EDITOR to configure",
                ],
                id="derivepassphrase-vault",
            ),
        ],
    )
    COLORFUL_COMMAND_INPUT = pytest.mark.parametrize(
        ["command_line", "input"],
        [
            (
                ["vault", "--import", "-"],
                '{"services": {"": {"length": 20}}}',
            ),
        ],
        ids=["cmd"],
    )
    ISATTY = pytest.mark.parametrize(
        "isatty",
        [False, True],
        ids=["notty", "tty"],
    )
    MASK_PROG_NAME = pytest.mark.parametrize(
        "mask_prog_name",
        [False, True],
        ids=["clear_prog_name", "masked_prog_name"],
    )
    MASK_VERSION = pytest.mark.parametrize(
        "mask_version", [False, True], ids=["clear_version", "masked_version"]
    )
    VERSION_OUTPUT_DATA = pytest.mark.parametrize(
        ["version_output", "prog_name", "version", "expected_parse"],
        [
            pytest.param(
                """\
derivepassphrase 0.4.0
Using cryptography 44.0.0

Supported foreign configuration formats: vault storeroom, vault v0.2,
    vault v0.3.
PEP 508 extras: export.
""",
                "derivepassphrase",
                "0.4.0",
                VersionOutputData(
                    derivation_schemes={},
                    foreign_configuration_formats={
                        "vault storeroom": True,
                        "vault v0.2": True,
                        "vault v0.3": True,
                    },
                    subcommands=frozenset(),
                    features={},
                    extras=frozenset({"export"}),
                ),
                id="derivepassphrase-0.4.0-export",
            ),
            pytest.param(
                """\
derivepassphrase 0.5

Supported derivation schemes: vault.
Known foreign configuration formats: vault storeroom, vault v0.2, vault v0.3.
Supported subcommands: export, vault.
No PEP 508 extras are active.
""",
                "derivepassphrase",
                "0.5",
                VersionOutputData(
                    derivation_schemes={"vault": True},
                    foreign_configuration_formats={
                        "vault storeroom": False,
                        "vault v0.2": False,
                        "vault v0.3": False,
                    },
                    subcommands=frozenset({"export", "vault"}),
                    features={},
                    extras=frozenset({}),
                ),
                id="derivepassphrase-0.5-plain",
            ),
            pytest.param(
                """\



inventpassphrase -1.3
Using not-a-library 7.12
Copyright 2025 Nobody.  All rights reserved.

Supported derivation schemes: nonsense.
Known derivation schemes: divination, /dev/random,
    geiger counter,
    crossword solver.
Supported foreign configuration formats: derivepassphrase, nonsense.
Known foreign configuration formats: divination v3.141592,
    /dev/random.
Supported subcommands: delete-all-files, dump-core.
Supported features: delete-while-open.
Known features: backups-are-nice-to-have.
PEP 508 extras: annoying-popups, delete-all-files,
    dump-core-depending-on-the-phase-of-the-moon.



""",
                "inventpassphrase",
                "-1.3",
                VersionOutputData(
                    derivation_schemes={
                        "nonsense": True,
                        "divination": False,
                        "/dev/random": False,
                        "geiger counter": False,
                        "crossword solver": False,
                    },
                    foreign_configuration_formats={
                        "derivepassphrase": True,
                        "nonsense": True,
                        "divination v3.141592": False,
                        "/dev/random": False,
                    },
                    subcommands=frozenset({"delete-all-files", "dump-core"}),
                    features={
                        "delete-while-open": True,
                        "backups-are-nice-to-have": False,
                    },
                    extras=frozenset({
                        "annoying-popups",
                        "delete-all-files",
                        "dump-core-depending-on-the-phase-of-the-moon",
                    }),
                ),
                id="inventpassphrase",
            ),
        ],
    )
    """Sample data for [`parse_version_output`][]."""


def parse_version_output(  # noqa: C901
    version_output: str,
    /,
    *,
    prog_name: str | None = cli_messages.PROG_NAME,
    version: str | None = cli_messages.VERSION,
) -> VersionOutputData:
    r"""Parse the output of the `--version` option.

    The version output contains two paragraphs.  The first paragraph
    details the version number, and the version number of any major
    libraries in use.  The second paragraph details known and supported
    passphrase derivation schemes, foreign configuration formats,
    subcommands and PEP 508 package extras.  For the schemes and
    formats, there is a "supported" line for supported items, and
    a "known" line for known but currently unsupported items (usually
    because of missing dependencies), either of which may be empty and
    thus omitted.  For extras, only active items are shown, and there is
    a separate message for the "no extras active" case.  Item lists may
    be spilled across multiple lines, but only at item boundaries, and
    the continuation lines are then indented.

    Args:
        version_output:
            The version output text to parse.
        prog_name:
            The program name to assert, defaulting to the true program
            name, `derivepassphrase`.  Set to `None` to disable this
            check.
        version:
            The program version to assert, defaulting to the true
            current version of `derivepassphrase`.  Set to `None` to
            disable this check.

    Examples:
        See [`Parametrize.VERSION_OUTPUT_DATA`][].

    """
    paragraphs: list[list[str]] = []
    paragraph: list[str] = []
    for line in version_output.splitlines(keepends=False):
        if not line.strip():
            if paragraph:
                paragraphs.append(paragraph.copy())
            paragraph.clear()
        elif paragraph and line.lstrip() != line:
            paragraph[-1] = f"{paragraph[-1]} {line.lstrip()}"
        else:
            paragraph.append(line)
    if paragraph:  # pragma: no branch
        paragraphs.append(paragraph.copy())
        paragraph.clear()
    assert paragraphs, (
        f"expected at least one paragraph of version output: {paragraphs!r}"
    )
    assert prog_name is None or prog_name in paragraphs[0][0], (
        f"first version output line should mention "
        f"{prog_name}: {paragraphs[0][0]!r}"
    )
    assert version is None or version in paragraphs[0][0], (
        f"first version output line should mention the version number "
        f"{version}: {paragraphs[0][0]!r}"
    )
    schemes: dict[str, bool] = {}
    formats: dict[str, bool] = {}
    subcommands: set[str] = set()
    extras: set[str] = set()
    features: dict[str, bool] = {}
    if len(paragraphs) < 2:  # pragma: no cover
        return VersionOutputData(
            derivation_schemes=schemes,
            foreign_configuration_formats=formats,
            subcommands=frozenset(subcommands),
            extras=frozenset(extras),
            features=features,
        )
    for line in paragraphs[1]:
        line_type, _, value = line.partition(":")
        if line_type == line:
            continue
        for item_ in re.split(r"(?:, *|.$)", value):
            item = item_.strip()
            if not item:
                continue
            if line_type == KnownLineType.SUPPORTED_FOREIGN_CONFS:
                formats[item] = True
            elif line_type == KnownLineType.UNAVAILABLE_FOREIGN_CONFS:
                formats[item] = False
            elif line_type == KnownLineType.SUPPORTED_SCHEMES:
                schemes[item] = True
            elif line_type == KnownLineType.UNAVAILABLE_SCHEMES:
                schemes[item] = False
            elif line_type == KnownLineType.SUPPORTED_SUBCOMMANDS:
                subcommands.add(item)
            elif line_type == KnownLineType.ENABLED_EXTRAS:
                extras.add(item)
            elif line_type == KnownLineType.SUPPORTED_FEATURES:
                features[item] = True
            elif line_type == KnownLineType.UNAVAILABLE_FEATURES:
                features[item] = False
            else:
                raise AssertionError(  # noqa: TRY003
                    f"Unknown version info line type: {line_type!r}"  # noqa: EM102
                )
    return VersionOutputData(
        derivation_schemes=schemes,
        foreign_configuration_formats=formats,
        subcommands=frozenset(subcommands),
        extras=frozenset(extras),
        features=features,
    )


class Test001VersionOutputParser:
    """Tests for the `--version` output parser."""

    @Parametrize.MASK_PROG_NAME
    @Parametrize.MASK_VERSION
    @Parametrize.VERSION_OUTPUT_DATA
    def test_parse_version_output(
        self,
        version_output: str,
        prog_name: str | None,
        version: str | None,
        mask_prog_name: bool,
        mask_version: bool,
        expected_parse: VersionOutputData,
    ) -> None:
        """The parsing machinery for expected version output data works."""
        prog_name = None if mask_prog_name else prog_name
        version = None if mask_version else version
        assert (
            parse_version_output(
                version_output, prog_name=prog_name, version=version
            )
            == expected_parse
        )


class TestHelpOutput:
    """Tests for all command-line interfaces' `--help` output."""

    # TODO(the-13th-letter): Do we actually need this?  What should we
    # check for?
    @Parametrize.HELP_OUTPUT_COMMAND_LINE
    def test_help_output(
        self,
        command_line: list[str],
        expected_lines: list[str],
    ) -> None:
        """The respective help text contains certain expected phrases.

        TODO: Do we actually need this?  What should we check for?

        """
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result = runner.invoke(
                cli.derivepassphrase,
                [*command_line, "--help"],
                catch_exceptions=False,
            )
        for line in expected_lines:
            assert result.clean_exit(empty_stderr=True, output=line), (
                "expected clean exit, and known help text"
            )

    @Parametrize.COMMAND_NON_EAGER_ARGUMENTS
    @Parametrize.EAGER_ARGUMENTS
    def test_eager_options(
        self,
        command: list[str],
        arguments: list[str],
        non_eager_arguments: list[str],
    ) -> None:
        """Eager options terminate option and argument processing."""
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result = runner.invoke(
                cli.derivepassphrase,
                [*command, *arguments, *non_eager_arguments],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), "expected clean exit"

    @Parametrize.ISATTY
    @Parametrize.COLORFUL_COMMAND_INPUT
    def test_automatic_color_mode(
        self,
        isatty: bool,
        command_line: list[str],
        input: str | None,
    ) -> None:
        """Auto-detect if color should be used.

        (The answer currently is always no. See the
        [`conventional-configurable-text-styling` wishlist
        entry][WISHLIST_ENTRY].)

        [WISHLIST_ENTRY]: https://the13thletter.info/derivepassphrase/0.x/wishlist/conventional-configurable-text-styling/

        """
        color = False
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result = runner.invoke(
                cli.derivepassphrase,
                command_line,
                input=input,
                catch_exceptions=False,
                color=isatty,
            )
        assert (
            not color
            or "\x1b[0m" in result.stderr
            or "\x1b[m" in result.stderr
        ), "Expected color, but found no ANSI reset sequence"
        assert color or "\x1b[" not in result.stderr, (
            "Expected no color, but found an ANSI control sequence"
        )


class TestVersionOutput:
    """Tests for all command-line interfaces' `--version` output."""

    def _test(
        self,
        command_line: list[str],
    ) -> VersionOutputData:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result = runner.invoke(
                cli.derivepassphrase,
                [*command_line, "--version"],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), "expected clean exit"
        assert result.stdout.strip(), "expected version output"
        return parse_version_output(result.stdout)

    def test_derivepassphrase_version_option_output(
        self,
    ) -> None:
        """The version output states supported features.

        The version output is parsed using [`parse_version_output`][].
        Format examples can be found in
        [`Parametrize.VERSION_OUTPUT_DATA`][].  Specifically, for the
        top-level `derivepassphrase` command, the output should contain
        the known and supported derivation schemes, and a list of
        subcommands.

        As a side effect, [`parse_version_output`][] guarantees that the
        first line contains both the correct program name as well as the
        correct program version number.

        """
        version_data = self._test([])
        actually_known_schemes = dict.fromkeys(_types.DerivationScheme, True)
        subcommands = set(_types.Subcommand)
        assert version_data.derivation_schemes == actually_known_schemes
        assert not version_data.foreign_configuration_formats
        assert version_data.subcommands == subcommands
        assert not version_data.features
        assert not version_data.extras

    def test_export_version_option_output(
        self,
    ) -> None:
        """The version output states supported features.

        The version output is parsed using [`parse_version_output`][].
        Format examples can be found in
        [`Parametrize.VERSION_OUTPUT_DATA`][].  Specifically, for the
        `export` command, the output should contain the known foreign
        configuration formats (but not marked as supported), and a list
        of subcommands.

        As a side effect, [`parse_version_output`][] guarantees that the
        first line contains both the correct program name as well as the
        correct program version number.

        """
        version_data = self._test(["export"])
        actually_known_formats: dict[str, bool] = {
            _types.ForeignConfigurationFormat.VAULT_STOREROOM: False,
            _types.ForeignConfigurationFormat.VAULT_V02: False,
            _types.ForeignConfigurationFormat.VAULT_V03: False,
        }
        subcommands = set(_types.ExportSubcommand)
        assert not version_data.derivation_schemes
        assert (
            version_data.foreign_configuration_formats
            == actually_known_formats
        )
        assert version_data.subcommands == subcommands
        assert not version_data.features
        assert not version_data.extras

    def test_export_vault_version_option_output(
        self,
    ) -> None:
        """The version output states supported features.

        The version output is parsed using [`parse_version_output`][].
        Format examples can be found in
        [`Parametrize.VERSION_OUTPUT_DATA`][].  Specifically, for the
        `export vault` subcommand, the output should contain the
        vault-specific subset of the known or supported foreign
        configuration formats, and a list of available PEP 508 extras.

        As a side effect, [`parse_version_output`][] guarantees that the
        first line contains both the correct program name as well as the
        correct program version number.

        """
        version_data = self._test(["export", "vault"])
        actually_known_formats: dict[str, bool] = {}
        actually_enabled_extras: set[str] = set()
        with contextlib.suppress(ModuleNotFoundError):
            from derivepassphrase.exporter import storeroom, vault_native  # noqa: I001,PLC0415

            actually_known_formats.update({
                _types.ForeignConfigurationFormat.VAULT_STOREROOM: not storeroom.STUBBED,
                _types.ForeignConfigurationFormat.VAULT_V02: not vault_native.STUBBED,
                _types.ForeignConfigurationFormat.VAULT_V03: not vault_native.STUBBED,
            })
        with contextlib.suppress(ModuleNotFoundError):
            import cryptography  # noqa: F401,PLC0415

            actually_enabled_extras.add(_types.PEP508Extra.EXPORT)
        assert not version_data.derivation_schemes
        assert (
            version_data.foreign_configuration_formats
            == actually_known_formats
        )
        assert not version_data.subcommands
        assert not version_data.features
        assert version_data.extras == actually_enabled_extras

    def test_vault_version_option_output(
        self,
    ) -> None:
        """The version output states supported features.

        The version output is parsed using [`parse_version_output`][].
        Format examples can be found in
        [`Parametrize.VERSION_OUTPUT_DATA`][].  Specifically, for the
        vault command, the output should not contain anything beyond the
        first paragraph.

        As a side effect, [`parse_version_output`][] guarantees that the
        first line contains both the correct program name as well as the
        correct program version number.

        """
        version_data = self._test(["vault"])
        ssh_key_supported = True

        def react_to_notimplementederror(
            _exc: BaseException,
        ) -> None:  # pragma: no cover[unused]
            nonlocal ssh_key_supported
            ssh_key_supported = False

        with exceptiongroup.catch({  # noqa: SIM117
            NotImplementedError: react_to_notimplementederror,
            Exception: lambda *_args: None,
        }):
            with ssh_agent.SSHAgentClient.ensure_agent_subcontext():
                pass
        features: dict[str, bool] = {
            _types.Feature.SSH_KEY: ssh_key_supported,
        }
        assert not version_data.derivation_schemes
        assert not version_data.foreign_configuration_formats
        assert not version_data.subcommands
        assert version_data.features == features
        assert not version_data.extras
