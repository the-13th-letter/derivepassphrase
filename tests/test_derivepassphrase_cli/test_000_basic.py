# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Tests for the `derivepassphrase vault` command-line interface."""

from __future__ import annotations

import contextlib
import copy
import errno
import json
import os
import pathlib
import shutil
import socket
import textwrap
import types
from typing import TYPE_CHECKING, ClassVar

import click.testing
import hypothesis
import pytest
from hypothesis import strategies
from typing_extensions import Any, NamedTuple, TypedDict

from derivepassphrase import _types, cli, ssh_agent, vault
from derivepassphrase._internals import (
    cli_helpers,
    cli_messages,
)
from tests import data, machinery
from tests.data import callables
from tests.machinery import hypothesis as hypothesis_machinery
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import NoReturn

    from typing_extensions import Literal, NotRequired

DUMMY_SERVICE = data.DUMMY_SERVICE
DUMMY_PASSPHRASE = data.DUMMY_PASSPHRASE
DUMMY_CONFIG_SETTINGS = data.DUMMY_CONFIG_SETTINGS
DUMMY_RESULT_PASSPHRASE = data.DUMMY_RESULT_PASSPHRASE
DUMMY_RESULT_KEY1 = data.DUMMY_RESULT_KEY1

DUMMY_KEY1_B64 = data.DUMMY_KEY1_B64
DUMMY_KEY2_B64 = data.DUMMY_KEY2_B64


class IncompatibleConfiguration(NamedTuple):
    other_options: list[tuple[str, ...]]
    needs_service: bool | None
    input: str | None


class SingleConfiguration(NamedTuple):
    needs_service: bool | None
    input: str | None
    check_success: bool


class OptionCombination(NamedTuple):
    options: list[str]
    incompatible: bool
    needs_service: bool | None
    input: str | None
    check_success: bool


PASSPHRASE_GENERATION_OPTIONS: list[tuple[str, ...]] = [
    ("--phrase",),
    ("--key",),
    ("--length", "20"),
    ("--repeat", "20"),
    ("--lower", "1"),
    ("--upper", "1"),
    ("--number", "1"),
    ("--space", "1"),
    ("--dash", "1"),
    ("--symbol", "1"),
]
CONFIGURATION_OPTIONS: list[tuple[str, ...]] = [
    ("--notes",),
    ("--config",),
    ("--delete",),
    ("--delete-globals",),
    ("--clear",),
]
CONFIGURATION_COMMANDS: list[tuple[str, ...]] = [
    ("--delete",),
    ("--delete-globals",),
    ("--clear",),
]
STORAGE_OPTIONS: list[tuple[str, ...]] = [("--export", "-"), ("--import", "-")]
INCOMPATIBLE: dict[tuple[str, ...], IncompatibleConfiguration] = {
    ("--phrase",): IncompatibleConfiguration(
        [("--key",), *CONFIGURATION_COMMANDS, *STORAGE_OPTIONS],
        True,
        DUMMY_PASSPHRASE,
    ),
    ("--key",): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ("--length", "20"): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ("--repeat", "20"): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ("--lower", "1"): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ("--upper", "1"): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ("--number", "1"): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ("--space", "1"): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ("--dash", "1"): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ("--symbol", "1"): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ("--notes",): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, None
    ),
    ("--config", "-p"): IncompatibleConfiguration(
        [("--delete",), ("--delete-globals",), ("--clear",), *STORAGE_OPTIONS],
        None,
        DUMMY_PASSPHRASE,
    ),
    ("--delete",): IncompatibleConfiguration(
        [("--delete-globals",), ("--clear",), *STORAGE_OPTIONS], True, None
    ),
    ("--delete-globals",): IncompatibleConfiguration(
        [("--clear",), *STORAGE_OPTIONS], False, None
    ),
    ("--clear",): IncompatibleConfiguration(STORAGE_OPTIONS, False, None),
    ("--export", "-"): IncompatibleConfiguration(
        [("--import", "-")], False, None
    ),
    ("--import", "-"): IncompatibleConfiguration([], False, None),
}
SINGLES: dict[tuple[str, ...], SingleConfiguration] = {
    ("--phrase",): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ("--key",): SingleConfiguration(True, None, False),
    ("--length", "20"): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ("--repeat", "20"): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ("--lower", "1"): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ("--upper", "1"): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ("--number", "1"): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ("--space", "1"): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ("--dash", "1"): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ("--symbol", "1"): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ("--notes",): SingleConfiguration(True, None, False),
    ("--config", "-p"): SingleConfiguration(None, DUMMY_PASSPHRASE, False),
    ("--delete",): SingleConfiguration(True, None, False),
    ("--delete-globals",): SingleConfiguration(False, None, True),
    ("--clear",): SingleConfiguration(False, None, True),
    ("--export", "-"): SingleConfiguration(False, None, True),
    ("--import", "-"): SingleConfiguration(False, '{"services": {}}', True),
}
INTERESTING_OPTION_COMBINATIONS: list[OptionCombination] = []
config: IncompatibleConfiguration | SingleConfiguration
for opt, config in INCOMPATIBLE.items():
    for opt2 in config.other_options:
        INTERESTING_OPTION_COMBINATIONS.extend([
            OptionCombination(
                options=list(opt + opt2),
                incompatible=True,
                needs_service=config.needs_service,
                input=config.input,
                check_success=False,
            ),
            OptionCombination(
                options=list(opt2 + opt),
                incompatible=True,
                needs_service=config.needs_service,
                input=config.input,
                check_success=False,
            ),
        ])
for opt, config in SINGLES.items():
    INTERESTING_OPTION_COMBINATIONS.append(
        OptionCombination(
            options=list(opt),
            incompatible=False,
            needs_service=config.needs_service,
            input=config.input,
            check_success=config.check_success,
        )
    )


def is_warning_line(line: str) -> bool:
    """Return true if the line is a warning line."""
    return " Warning: " in line or " Deprecation warning: " in line


def is_harmless_config_import_warning(record: tuple[str, int, str]) -> bool:
    """Return true if the warning is harmless, during config import."""
    possible_warnings = [
        "Replacing invalid value ",
        "Removing ineffective setting ",
        (
            "Setting a global passphrase is ineffective "
            "because a key is also set."
        ),
        (
            "Setting a service passphrase is ineffective "
            "because a key is also set:"
        ),
    ]
    return any(
        machinery.warning_emitted(w, [record]) for w in possible_warnings
    )


def assert_vault_config_is_indented_and_line_broken(
    config_txt: str,
    /,
) -> None:
    """Return true if the vault configuration is indented and line broken.

    Indented and rewrapped vault configurations as produced by
    `json.dump` contain the closing '}' of the '$.services' object
    on a separate, indented line:

    ~~~~
    {
      "services": {
        ...
      }  <-- this brace here
    }
    ~~~~

    or, if there are no services, then the indented line

    ~~~~
      "services": {}
    ~~~~

    Both variations may end with a comma if there are more top-level
    keys.

    """
    known_indented_lines = {
        "}",
        "},",
        '"services": {}',
        '"services": {},',
    }
    assert any([
        line.strip() in known_indented_lines and line.startswith((" ", "\t"))
        for line in config_txt.splitlines()
    ])


class Strategies:
    @staticmethod
    def notes(*, max_size: int = 512) -> strategies.SearchStrategy[str]:
        return strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters="\n"
            ),
            min_size=1,
            max_size=max_size,
        )


class Parametrize(types.SimpleNamespace):
    """Common test parametrizations."""

    AUTO_PROMPT = pytest.mark.parametrize(
        "auto_prompt", [False, True], ids=["normal_prompt", "auto_prompt"]
    )
    CHARSET_NAME = pytest.mark.parametrize(
        "charset_name", ["lower", "upper", "number", "space", "dash", "symbol"]
    )
    CONFIG_EDITING_VIA_CONFIG_FLAG_FAILURES = pytest.mark.parametrize(
        ["command_line", "input", "err_text"],
        [
            pytest.param(
                [],
                "",
                "Cannot update the global settings without any given settings",
                id="None",
            ),
            pytest.param(
                ["--", "sv"],
                "",
                "Cannot update the service-specific settings without any given settings",
                id="None-sv",
            ),
            pytest.param(
                ["--phrase", "--", "sv"],
                "\n",
                "No passphrase was given",
                id="phrase-sv",
            ),
            pytest.param(
                ["--phrase", "--", "sv"],
                "",
                "No passphrase was given",
                id="phrase-sv-eof",
            ),
            pytest.param(
                ["--key"],
                "\n",
                "No SSH key was selected",
                id="key-sv",
            ),
            pytest.param(
                ["--key"],
                "",
                "No SSH key was selected",
                id="key-sv-eof",
            ),
        ],
    )
    CONFIG_EDITING_VIA_CONFIG_FLAG = pytest.mark.parametrize(
        ["command_line", "input", "starting_config", "result_config"],
        [
            pytest.param(
                ["--phrase"],
                "my passphrase\n",
                {"global": {"phrase": "abc"}, "services": {}},
                {"global": {"phrase": "my passphrase"}, "services": {}},
                id="phrase",
            ),
            pytest.param(
                ["--key"],
                "1\n",
                {"global": {"phrase": "abc"}, "services": {}},
                {
                    "global": {"key": DUMMY_KEY1_B64, "phrase": "abc"},
                    "services": {},
                },
                id="key",
            ),
            pytest.param(
                ["--phrase", "--", "sv"],
                "my passphrase\n",
                {"global": {"phrase": "abc"}, "services": {}},
                {
                    "global": {"phrase": "abc"},
                    "services": {"sv": {"phrase": "my passphrase"}},
                },
                id="phrase-sv",
            ),
            pytest.param(
                ["--key", "--", "sv"],
                "1\n",
                {"global": {"phrase": "abc"}, "services": {}},
                {
                    "global": {"phrase": "abc"},
                    "services": {"sv": {"key": DUMMY_KEY1_B64}},
                },
                id="key-sv",
            ),
            pytest.param(
                ["--key", "--length", "15", "--", "sv"],
                "1\n",
                {"global": {"phrase": "abc"}, "services": {}},
                {
                    "global": {"phrase": "abc"},
                    "services": {"sv": {"key": DUMMY_KEY1_B64, "length": 15}},
                },
                id="key-length-sv",
            ),
        ],
    )
    BASE_CONFIG_WITH_KEY_VARIATIONS = pytest.mark.parametrize(
        "config",
        [
            pytest.param(
                {
                    "global": {"key": DUMMY_KEY1_B64},
                    "services": {DUMMY_SERVICE: {}},
                },
                id="global_config",
            ),
            pytest.param(
                {"services": {DUMMY_SERVICE: {"key": DUMMY_KEY2_B64}}},
                id="service_config",
            ),
            pytest.param(
                {
                    "global": {"key": DUMMY_KEY1_B64},
                    "services": {DUMMY_SERVICE: {"key": DUMMY_KEY2_B64}},
                },
                id="full_config",
            ),
        ],
    )
    CONFIG_WITH_KEY = pytest.mark.parametrize(
        "config",
        [
            pytest.param(
                {
                    "global": {"key": DUMMY_KEY1_B64},
                    "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS},
                },
                id="global",
            ),
            pytest.param(
                {
                    "global": {"phrase": DUMMY_PASSPHRASE.rstrip("\n")},
                    "services": {
                        DUMMY_SERVICE: {
                            "key": DUMMY_KEY1_B64,
                            **DUMMY_CONFIG_SETTINGS,
                        }
                    },
                },
                id="service",
            ),
        ],
    )
    CONFIG_WITH_PHRASE = pytest.mark.parametrize(
        "config",
        [
            pytest.param(
                {
                    "global": {"phrase": DUMMY_PASSPHRASE.rstrip("\n")},
                    "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS},
                },
                id="global",
            ),
            pytest.param(
                {
                    "global": {
                        "phrase": DUMMY_PASSPHRASE.rstrip("\n")
                        + "XXX"
                        + DUMMY_PASSPHRASE.rstrip("\n")
                    },
                    "services": {
                        DUMMY_SERVICE: {
                            "phrase": DUMMY_PASSPHRASE.rstrip("\n"),
                            **DUMMY_CONFIG_SETTINGS,
                        }
                    },
                },
                id="service",
            ),
        ],
    )
    VALID_TEST_CONFIGS = pytest.mark.parametrize(
        "config",
        [conf.config for conf in data.TEST_CONFIGS if conf.is_valid()],
    )
    KEY_OVERRIDING_IN_CONFIG = pytest.mark.parametrize(
        ["config", "command_line"],
        [
            pytest.param(
                {
                    "global": {"key": DUMMY_KEY1_B64},
                    "services": {},
                },
                ["--config", "-p"],
                id="global",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {
                            "key": DUMMY_KEY1_B64,
                            **DUMMY_CONFIG_SETTINGS,
                        },
                    },
                },
                ["--config", "-p", "--", DUMMY_SERVICE],
                id="service",
            ),
            pytest.param(
                {
                    "global": {"key": DUMMY_KEY1_B64},
                    "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()},
                },
                ["--config", "-p", "--", DUMMY_SERVICE],
                id="service-over-global",
            ),
        ],
    )
    EXPORT_FORMAT_OPTIONS = pytest.mark.parametrize(
        "export_options",
        [
            [],
            ["--export-as=sh"],
        ],
        ids=["json-format", "sh-format"],
    )
    KEY_INDEX = pytest.mark.parametrize(
        "key_index", [1, 2, 3], ids=lambda i: f"index{i}"
    )
    UNICODE_NORMALIZATION_ERROR_INPUTS = pytest.mark.parametrize(
        ["main_config", "command_line", "input", "error_message"],
        [
            pytest.param(
                textwrap.dedent(r"""
                [vault]
                default-unicode-normalization-form = 'XXX'
                """),
                ["--import", "-"],
                json.dumps({
                    "services": {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        "with_normalization": {"phrase": "D\u00fcsseldorf"},
                    },
                }),
                (
                    "Invalid value 'XXX' for config key "
                    "vault.default-unicode-normalization-form"
                ),
                id="global",
            ),
            pytest.param(
                textwrap.dedent(r"""
                [vault.unicode-normalization-form]
                with_normalization = 'XXX'
                """),
                ["--import", "-"],
                json.dumps({
                    "services": {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        "with_normalization": {"phrase": "D\u00fcsseldorf"},
                    },
                }),
                (
                    "Invalid value 'XXX' for config key "
                    "vault.with_normalization.unicode-normalization-form"
                ),
                id="service",
            ),
            pytest.param(
                textwrap.dedent(r"""
                [vault]
                default-unicode-normalization-form = 'XXX'
                """),
                ["--config", "--phrase"],
                DUMMY_PASSPHRASE,
                (
                    "Invalid value 'XXX' for config key "
                    "vault.default-unicode-normalization-form"
                ),
                id="configure global passphrase",
            ),
            pytest.param(
                textwrap.dedent(r"""
                [vault]
                default-unicode-normalization-form = 'XXX'
                """),
                ["--config", "--phrase", "--", DUMMY_SERVICE],
                DUMMY_PASSPHRASE,
                (
                    "Invalid value 'XXX' for config key "
                    "vault.default-unicode-normalization-form"
                ),
                id="configure service passphrase",
            ),
            pytest.param(
                textwrap.dedent(r"""
                [vault]
                default-unicode-normalization-form = 'XXX'
                """),
                ["--phrase", "--", DUMMY_SERVICE],
                DUMMY_PASSPHRASE,
                (
                    "Invalid value 'XXX' for config key "
                    "vault.default-unicode-normalization-form"
                ),
                id="interactive passphrase",
            ),
        ],
    )
    UNICODE_NORMALIZATION_WARNING_INPUTS = pytest.mark.parametrize(
        ["main_config", "command_line", "input", "warning_message"],
        [
            pytest.param(
                "",
                ["--import", "-"],
                json.dumps({
                    "global": {"phrase": "Du\u0308sseldorf"},
                    "services": {},
                }),
                "The $.global passphrase is not NFC-normalized",
                id="global-NFC",
            ),
            pytest.param(
                "",
                ["--import", "-"],
                json.dumps({
                    "services": {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        "weird entry name": {"phrase": "Du\u0308sseldorf"},
                    }
                }),
                (
                    'The $.services["weird entry name"] passphrase '
                    "is not NFC-normalized"
                ),
                id="service-weird-name-NFC",
            ),
            pytest.param(
                "",
                ["--config", "-p", "--", DUMMY_SERVICE],
                "Du\u0308sseldorf",
                (
                    f"The $.services.{DUMMY_SERVICE} passphrase "
                    f"is not NFC-normalized"
                ),
                id="config-NFC",
            ),
            pytest.param(
                "",
                ["-p", "--", DUMMY_SERVICE],
                "Du\u0308sseldorf",
                "The interactive input passphrase is not NFC-normalized",
                id="direct-input-NFC",
            ),
            pytest.param(
                textwrap.dedent(r"""
                [vault]
                default-unicode-normalization-form = 'NFD'
                """),
                ["--import", "-"],
                json.dumps({
                    "global": {
                        "phrase": "D\u00fcsseldorf",
                    },
                    "services": {},
                }),
                "The $.global passphrase is not NFD-normalized",
                id="global-NFD",
            ),
            pytest.param(
                textwrap.dedent(r"""
                [vault]
                default-unicode-normalization-form = 'NFD'
                """),
                ["--import", "-"],
                json.dumps({
                    "services": {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        "weird entry name": {"phrase": "D\u00fcsseldorf"},
                    },
                }),
                (
                    'The $.services["weird entry name"] passphrase '
                    "is not NFD-normalized"
                ),
                id="service-weird-name-NFD",
            ),
            pytest.param(
                textwrap.dedent(r"""
                [vault.unicode-normalization-form]
                'weird entry name 2' = 'NFKD'
                """),
                ["--import", "-"],
                json.dumps({
                    "services": {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        "weird entry name 1": {"phrase": "D\u00fcsseldorf"},
                        "weird entry name 2": {"phrase": "D\u00fcsseldorf"},
                    },
                }),
                (
                    'The $.services["weird entry name 2"] passphrase '
                    "is not NFKD-normalized"
                ),
                id="service-weird-name-2-NFKD",
            ),
        ],
    )
    MODERN_EDITOR_INTERFACE = pytest.mark.parametrize(
        "modern_editor_interface", [False, True], ids=["legacy", "modern"]
    )
    NOTES_PLACEMENT = pytest.mark.parametrize(
        ["notes_placement", "placement_args"],
        [
            pytest.param("after", ["--print-notes-after"], id="after"),
            pytest.param("before", ["--print-notes-before"], id="before"),
        ],
    )
    VAULT_CHARSET_OPTION = pytest.mark.parametrize(
        "option",
        [
            "--lower",
            "--upper",
            "--number",
            "--space",
            "--dash",
            "--symbol",
            "--repeat",
            "--length",
        ],
    )
    OPTION_COMBINATIONS_INCOMPATIBLE = pytest.mark.parametrize(
        ["options", "service"],
        [
            pytest.param(o.options, o.needs_service, id=" ".join(o.options))
            for o in INTERESTING_OPTION_COMBINATIONS
            if o.incompatible
        ],
    )
    OPTION_COMBINATIONS_SERVICE_NEEDED = pytest.mark.parametrize(
        ["options", "service", "input", "check_success"],
        [
            pytest.param(
                o.options,
                o.needs_service,
                o.input,
                o.check_success,
                id=" ".join(o.options),
            )
            for o in INTERESTING_OPTION_COMBINATIONS
            if not o.incompatible
        ],
    )
    TRY_RACE_FREE_IMPLEMENTATION = pytest.mark.parametrize(
        "try_race_free_implementation",
        [False, True],
        ids=["racy", "maybe-race-free"],
    )


class TestHelp:
    """Tests related to help output."""

    def test_help_output(
        self,
    ) -> None:
        """The `--help` option emits help text."""
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
                cli.derivepassphrase_vault,
                ["--help"],
                catch_exceptions=False,
            )
        assert result.clean_exit(
            empty_stderr=True, output="Passphrase generation:\n"
        ), "expected clean exit, and option groups in help text"
        assert result.clean_exit(
            empty_stderr=True, output="Use $VISUAL or $EDITOR to configure"
        ), "expected clean exit, and option group epilog in help text"


class TestDerivedPassphraseConstraints:
    """Tests for (derived) passphrase constraints."""

    def _test(self, command_line: list[str]) -> machinery.ReadableResult:
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
            monkeypatch.setattr(
                cli_helpers,
                "prompt_for_passphrase",
                callables.auto_prompt,
            )
            return runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )

    @Parametrize.CHARSET_NAME
    def test_disable_character_set(
        self,
        charset_name: str,
    ) -> None:
        """Named character classes can be disabled on the command-line."""
        option = f"--{charset_name}"
        charset = vault.Vault.CHARSETS[charset_name].decode("ascii")
        result = self._test([option, "0", "-p", "--", DUMMY_SERVICE])
        assert result.clean_exit(empty_stderr=True), "expected clean exit:"
        for c in charset:
            assert c not in result.stdout, (
                f"derived password contains forbidden character {c!r}"
            )

    def test_disable_repetition(
        self,
    ) -> None:
        """Character repetition can be disabled on the command-line."""
        result = self._test(["--repeat", "0", "-p", "--", DUMMY_SERVICE])
        assert result.clean_exit(empty_stderr=True), (
            "expected clean exit and empty stderr"
        )
        passphrase = result.stdout.rstrip("\r\n")
        for i in range(len(passphrase) - 1):
            assert passphrase[i : i + 1] != passphrase[i + 1 : i + 2], (
                f"derived password contains repeated character "
                f"at position {i}: {result.stdout!r}"
            )


class TestPhraseBasic:
    """Tests for master passphrase configuration: basic."""

    def _test(
        self,
        command_line: list[str],
        /,
        *,
        config: _types.VaultConfig = {  # noqa: B006
            "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}
        },
        auto_prompt: bool = False,
        multiline: bool = False,
    ) -> None:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )

            def phrase_from_key(*_args: Any, **_kwargs: Any) -> NoReturn:
                pytest.fail("Attempted to use a key in a phrase-based test!")

            monkeypatch.setattr(
                vault.Vault, "phrase_from_key", phrase_from_key
            )
            if auto_prompt:
                monkeypatch.setattr(
                    cli_helpers,
                    "prompt_for_passphrase",
                    callables.auto_prompt,
                )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=None if auto_prompt else DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        if multiline:
            assert result.clean_exit(), "expected clean exit"
        else:
            assert result.clean_exit(empty_stderr=True), (
                "expected clean exit and empty stderr"
            )
        assert result.stdout, "expected program output"
        last_line = (
            result.stdout.splitlines(keepends=True)[-1]
            if multiline
            else result.stdout
        )
        assert (
            last_line.rstrip("\n").encode("UTF-8") == DUMMY_RESULT_PASSPHRASE
        ), "expected known output"

    @Parametrize.CONFIG_WITH_PHRASE
    def test_phrase_from_config(
        self,
        config: _types.VaultConfig,
    ) -> None:
        """A stored configured master passphrase will be used."""
        self._test(["--", DUMMY_SERVICE], config=config)

    @Parametrize.AUTO_PROMPT
    def test_phrase_from_command_line(
        self,
        auto_prompt: bool,
    ) -> None:
        """A master passphrase requested on the command-line will be used."""
        self._test(
            ["-p", "--", DUMMY_SERVICE],
            auto_prompt=auto_prompt,
            multiline=True,
        )


class TestKeyBasic:
    """Tests for SSH key configuration: basic."""

    def _test(
        self,
        command_line: list[str],
        /,
        *,
        config: _types.VaultConfig = {  # noqa: B006
            "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}
        },
        multiline: bool = False,
        input: str | bytes | None = None,
    ) -> None:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            monkeypatch.setattr(
                cli_helpers,
                "get_suitable_ssh_keys",
                callables.suitable_ssh_keys,
            )
            monkeypatch.setattr(
                vault.Vault,
                "phrase_from_key",
                callables.phrase_from_key,
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=input,
                catch_exceptions=False,
            )
        if multiline:
            assert result.clean_exit(), "expected clean exit"
        else:
            assert result.clean_exit(empty_stderr=True), (
                "expected clean exit and empty stderr"
            )
        assert result.stdout, "expected program output"
        last_line = (
            result.stdout.splitlines(keepends=True)[-1]
            if multiline
            else result.stdout
        )
        assert (
            last_line.rstrip("\n").encode("UTF-8") != DUMMY_RESULT_PASSPHRASE
        ), "known false output: phrase-based instead of key-based"
        assert last_line.rstrip("\n").encode("UTF-8") == DUMMY_RESULT_KEY1, (
            "expected known output"
        )

    @Parametrize.CONFIG_WITH_KEY
    def test_key_from_config(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
        config: _types.VaultConfig,
    ) -> None:
        """A stored configured SSH key will be used."""
        del running_ssh_agent
        self._test(["--", DUMMY_SERVICE], config=config)

    def test_key_from_command_line(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
    ) -> None:
        """An SSH key requested on the command-line will be used."""
        del running_ssh_agent
        self._test(["-k", "--", DUMMY_SERVICE], input="1\n", multiline=True)


class TestPhraseAndKeyOverriding:
    """Tests for master passphrase and SSH key configuration: overriding."""

    def _test(
        self,
        command_line: list[str],
        /,
        *,
        config: _types.VaultConfig = {  # noqa: B006
            "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}
        },
        input: str | bytes | None = None,
    ) -> machinery.ReadableResult:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient,
                "list_keys",
                callables.list_keys,
            )
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, "sign", callables.sign
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=input,
                catch_exceptions=False,
            )
        assert result.clean_exit(), "expected clean exit"
        return result

    @Parametrize.BASE_CONFIG_WITH_KEY_VARIATIONS
    @Parametrize.KEY_INDEX
    def test_key_override_on_command_line(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
        config: _types.VaultConfig,
        key_index: int,
    ) -> None:
        """A command-line SSH key will override the configured key."""
        del running_ssh_agent
        result = self._test(
            ["-k", "--", DUMMY_SERVICE],
            config=config,
            input=f"{key_index}\n",
        )
        assert result.stdout, "expected program output"
        assert result.stderr, "expected stderr"
        assert "Error:" not in result.stderr, (
            "expected no error messages on stderr"
        )

    def test_service_phrase_if_key_in_global_config(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
    ) -> None:
        """A configured passphrase does not override a configured key."""
        del running_ssh_agent
        result = self._test(
            ["--", DUMMY_SERVICE],
            config={
                "global": {"key": DUMMY_KEY1_B64},
                "services": {
                    DUMMY_SERVICE: {
                        "phrase": DUMMY_PASSPHRASE.rstrip("\n"),
                        **DUMMY_CONFIG_SETTINGS,
                    }
                },
            },
        )
        assert result.stdout, "expected program output"
        last_line = result.stdout.splitlines(True)[-1]
        assert (
            last_line.rstrip("\n").encode("UTF-8") != DUMMY_RESULT_PASSPHRASE
        ), "known false output: phrase-based instead of key-based"
        assert last_line.rstrip("\n").encode("UTF-8") == DUMMY_RESULT_KEY1, (
            "expected known output"
        )

    @Parametrize.KEY_OVERRIDING_IN_CONFIG
    def test_setting_phrase_thus_overriding_key_in_config(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
        caplog: pytest.LogCaptureFixture,
        config: _types.VaultConfig,
        command_line: list[str],
    ) -> None:
        """Configuring a passphrase atop an SSH key works, but warns."""
        del running_ssh_agent
        result = self._test(
            command_line, config=config, input=DUMMY_PASSPHRASE
        )
        assert not result.stdout.strip(), "expected no program output"
        assert result.stderr, "expected known error output"
        err_lines = result.stderr.splitlines(False)
        assert err_lines[0].startswith("Passphrase:")
        assert machinery.warning_emitted(
            "Setting a service passphrase is ineffective ",
            caplog.record_tuples,
        ) or machinery.warning_emitted(
            "Setting a global passphrase is ineffective ",
            caplog.record_tuples,
        ), "expected known warning message"
        assert all(map(is_warning_line, result.stderr.splitlines(True)))
        assert all(
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), "unexpected error output"


class TestInvalidCommandLines:
    """Tests concerning invalid command-lines."""

    @contextlib.contextmanager
    def _setup_environment(
        self,
        /,
        *,
        auto_prompt: bool = False,
        config: _types.VaultConfig = {  # noqa: B006
            "services": {
                DUMMY_SERVICE: {**DUMMY_CONFIG_SETTINGS},
            },
        },
    ) -> Iterator[machinery.CliRunner]:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            if auto_prompt:
                monkeypatch.setattr(
                    cli_helpers,
                    "prompt_for_passphrase",
                    callables.auto_prompt,
                )
            yield runner

    def _call(
        self,
        command_line: list[str],
        /,
        *,
        config: _types.VaultConfig = {  # noqa: B006
            "services": {
                DUMMY_SERVICE: {**DUMMY_CONFIG_SETTINGS},
            },
        },
        input: str | bytes | None = None,
        runner: machinery.CliRunner | None = None,
    ) -> machinery.ReadableResult:
        if runner:
            return runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=input,
                catch_exceptions=False,
            )
        with self._setup_environment(
            config=config, auto_prompt=input is not None
        ) as runner2:
            return runner2.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=input,
                catch_exceptions=False,
            )

    @Parametrize.VAULT_CHARSET_OPTION
    def test_invalid_argument_range(
        self,
        option: str,
    ) -> None:
        """Requesting invalidly many characters from a class fails."""
        with self._setup_environment() as runner:
            for value in "-42", "invalid":
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    [option, value, "-p", "--", DUMMY_SERVICE],
                    input=DUMMY_PASSPHRASE,
                    catch_exceptions=False,
                )
                assert result.error_exit(error="Invalid value"), (
                    "expected error exit and known error message"
                )

    @Parametrize.OPTION_COMBINATIONS_SERVICE_NEEDED
    def test_service_needed(
        self,
        options: list[str],
        service: bool | None,
        input: str | None,
        check_success: bool,
    ) -> None:
        """We require or forbid a service argument, depending on options."""
        config: _types.VaultConfig = {
            "global": {"phrase": "abc"},
            "services": {},
        }
        result = self._call(
            options if service else [*options, "--", DUMMY_SERVICE],
            config=config,
            input=input,
        )
        if service is not None:
            err_msg = (
                " requires a SERVICE"
                if service
                else " does not take a SERVICE argument"
            )
            assert result.error_exit(error=err_msg), (
                "expected error exit and known error message"
            )
            if check_success:
                result = self._call(
                    [*options, "--", DUMMY_SERVICE] if service else options,
                    config=config,
                    input=input,
                )
                assert result.clean_exit(empty_stderr=True), (
                    "expected clean exit"
                )
        else:
            assert result.clean_exit(empty_stderr=True), "expected clean exit"

    def test_empty_service_name_causes_warning(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Using an empty service name (where permissible) warns.

        Only the `--config` option can optionally take a service name.

        """

        def is_expected_warning(record: tuple[str, int, str]) -> bool:
            return is_harmless_config_import_warning(
                record
            ) or machinery.warning_emitted(
                "An empty SERVICE is not supported by vault(1)", [record]
            )

        def check_result(result: machinery.ReadableResult) -> None:
            assert result.clean_exit(empty_stderr=False), "expected clean exit"
            assert result.stderr is not None, "expected known error output"
            assert all(map(is_expected_warning, caplog.record_tuples)), (
                "expected known error output"
            )

        with self._setup_environment(
            config={"services": {}}, auto_prompt=True
        ) as runner:
            result = self._call(
                ["--config", "--length=30", "--", ""], runner=runner
            )
            check_result(result)
            assert cli_helpers.load_config() == {
                "global": {"length": 30},
                "services": {},
            }, "requested configuration change was not applied"
            caplog.clear()
            result = self._call(
                ["--import", "-"],
                input=json.dumps({"services": {"": {"length": 40}}}),
                runner=runner,
            )
            check_result(result)
            assert cli_helpers.load_config() == {
                "global": {"length": 30},
                "services": {"": {"length": 40}},
            }, "requested configuration change was not applied"

    @Parametrize.OPTION_COMBINATIONS_INCOMPATIBLE
    def test_incompatible_options(
        self,
        options: list[str],
        service: bool | None,
    ) -> None:
        """Incompatible options are detected."""
        result = self._call(
            [*options, "--", DUMMY_SERVICE] if service else options,
            input=DUMMY_PASSPHRASE,
        )
        assert result.error_exit(error="mutually exclusive with "), (
            "expected error exit and known error message"
        )

    def test_no_arguments(self) -> None:
        """Calling `derivepassphrase vault` without any arguments fails."""
        result = self._call([], input=DUMMY_PASSPHRASE)
        assert result.error_exit(
            error="Deriving a passphrase requires a SERVICE"
        ), "expected error exit and known error message"

    def test_no_passphrase_or_key(
        self,
    ) -> None:
        """Deriving a passphrase without a passphrase or key fails."""
        result = self._call(["--", DUMMY_SERVICE], input=DUMMY_PASSPHRASE)
        assert result.error_exit(error="No passphrase or key was given"), (
            "expected error exit and known error message"
        )


class TestImportConfigValid:
    """Tests concerning `vault` configuration imports: valid imports."""

    def _test(
        self,
        /,
        *,
        caplog: pytest.LogCaptureFixture,
        config: _types.VaultConfig,
    ) -> None:
        config2 = copy.deepcopy(config)
        _types.clean_up_falsy_vault_config_values(config2)
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={"services": {}},
                )
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--import", "-"],
                input=json.dumps(config),
                catch_exceptions=False,
            )
            config_txt = cli_helpers.config_filename(
                subsystem="vault"
            ).read_text(encoding="UTF-8")
            config3 = json.loads(config_txt)
        assert result.clean_exit(empty_stderr=False), "expected clean exit"
        assert config3 == config2, "config not imported correctly"
        assert not result.stderr or all(
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), "unexpected error output"
        assert_vault_config_is_indented_and_line_broken(config_txt)

    @Parametrize.VALID_TEST_CONFIGS
    def test_normal_config(
        self,
        caplog: pytest.LogCaptureFixture,
        config: Any,
    ) -> None:
        """Importing a configuration works."""
        self._test(caplog=caplog, config=config)

    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(
        conf=hypothesis_machinery.smudged_vault_test_config(
            strategies.sampled_from([
                conf for conf in data.TEST_CONFIGS if conf.is_valid()
            ])
        )
    )
    def test_smudged_config(
        self,
        caplog: pytest.LogCaptureFixture,
        conf: data.VaultTestConfig,
    ) -> None:
        """Importing a smudged configuration works.

        Tested via hypothesis.

        """
        # Reset caplog between hypothesis runs.
        caplog.clear()
        self._test(caplog=caplog, config=conf.config)


class TestImportConfigInvalid:
    """Tests concerning `vault` configuration imports: invalid imports."""

    @contextlib.contextmanager
    def _setup_environment(self) -> Iterator[machinery.CliRunner]:
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
            yield runner

    def _test(
        self,
        command_line: list[str],
        /,
        *,
        input: str | bytes | None = None,
    ) -> machinery.ReadableResult:
        with self._setup_environment() as runner:
            return runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=input,
                catch_exceptions=False,
            )

    def test_not_a_vault_config(
        self,
    ) -> None:
        """Importing an invalid config fails."""
        result = self._test(["--import", "-"], input="null")
        assert result.error_exit(error="Invalid vault config"), (
            "expected error exit and known error message"
        )

    def test_not_json_data(
        self,
    ) -> None:
        """Importing an invalid config fails."""
        result = self._test(
            ["--import", "-"], input="This string is not valid JSON."
        )
        assert result.error_exit(error="cannot decode JSON"), (
            "expected error exit and known error message"
        )

    def test_not_a_file(
        self,
    ) -> None:
        """Importing an invalid config fails."""
        with self._setup_environment() as runner:
            # `_setup_environment` (via `isolated_vault_config`) ensures
            # the configuration is valid JSON.  So, to pass an actual
            # broken configuration, we must open the configuration file
            # ourselves afterwards, inside the context.
            cli_helpers.config_filename(subsystem="vault").write_text(
                "This string is not valid JSON.\n", encoding="UTF-8"
            )
            dname = cli_helpers.config_filename(subsystem=None)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--import", os.fsdecode(dname)],
                catch_exceptions=False,
            )
        # The Annoying OS uses EACCES, other OSes use EISDIR.
        assert result.error_exit(
            error=os.strerror(errno.EISDIR)
        ) or result.error_exit(error=os.strerror(errno.EACCES)), (
            "expected error exit and known error message"
        )


class TestExportConfigValid:
    """Tests concerning `vault` configuration exports: valid exports."""

    def _assert_result(
        self,
        result: machinery.ReadableResult,
        /,
        *,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        assert result.clean_exit(empty_stderr=False), "expected clean exit"
        assert not result.stderr or all(
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), "unexpected error output"

    def _test(
        self,
        /,
        *,
        caplog: pytest.LogCaptureFixture,
        config: _types.VaultConfig,
        use_import: bool = False,
    ) -> None:
        config2 = copy.deepcopy(config)
        _types.clean_up_falsy_vault_config_values(config2)
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={"services": {}},
                )
            )
            if use_import:
                result1 = runner.invoke(
                    cli.derivepassphrase_vault,
                    ["--import", "-"],
                    input=json.dumps(config),
                    catch_exceptions=False,
                )
                self._assert_result(result1, caplog=caplog)
            else:
                with cli_helpers.config_filename(subsystem="vault").open(
                    "w", encoding="UTF-8"
                ) as outfile:
                    # Ensure the config is written on one line.
                    json.dump(config, outfile, indent=None)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--export", "-"],
                catch_exceptions=False,
            )
        self._assert_result(result, caplog=caplog)
        config3 = json.loads(result.stdout)
        assert config3 == config2, "config not exported correctly"
        assert_vault_config_is_indented_and_line_broken(result.stdout)

    @Parametrize.VALID_TEST_CONFIGS
    def test_normal_config(
        self,
        caplog: pytest.LogCaptureFixture,
        config: Any,
    ) -> None:
        """Exporting a configuration works."""
        self._test(caplog=caplog, config=config, use_import=False)

    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(
        conf=hypothesis_machinery.smudged_vault_test_config(
            strategies.sampled_from([
                conf for conf in data.TEST_CONFIGS if conf.is_valid()
            ])
        )
    )
    def test_reexport_smudged_config(
        self,
        caplog: pytest.LogCaptureFixture,
        conf: data.VaultTestConfig,
    ) -> None:
        """Re-exporting a smudged configuration works.

        Tested via hypothesis.

        """
        # Reset caplog between hypothesis runs.
        caplog.clear()
        self._test(caplog=caplog, config=conf.config, use_import=True)

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_no_stored_settings(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting the default, empty config works."""
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
            cli_helpers.config_filename(subsystem="vault").unlink(
                missing_ok=True
            )
            result = runner.invoke(
                # Test parent context navigation by not calling
                # `cli.derivepassphrase_vault` directly.  Used e.g. in
                # the `--export-as=sh` section to autoconstruct the
                # program name correctly.
                cli.derivepassphrase,
                ["vault", "--export", "-", *export_options],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), "expected clean exit"
        assert result.stdout.startswith("#!") or json.loads(result.stdout) == {
            "services": {}
        }


class TestExportConfigInvalid:
    """Tests concerning `vault` configuration exports: invalid exports."""

    @contextlib.contextmanager
    def _test(
        self,
        command_line: list[str],
        /,
        *,
        config: _types.VaultConfig = {"services": {}},  # noqa: B006
        error_messages: tuple[str, ...] = (),
    ) -> Iterator[list[str]]:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            yield command_line
            result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input="null",
                catch_exceptions=False,
            )
        assert any([result.error_exit(error=msg) for msg in error_messages]), (
            "expected error exit and known error message"
        )

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_bad_stored_config(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        with self._test(
            ["--export", "-", *export_options],
            config=None,  # type: ignore[arg-type,typeddict-item]
            error_messages=("Cannot load vault settings:",),
        ):
            pass

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_not_a_file(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        with self._test(
            ["--export", "-", *export_options],
            error_messages=("Cannot load vault settings:",),
        ):
            config_file = cli_helpers.config_filename(subsystem="vault")
            config_file.unlink(missing_ok=True)
            config_file.mkdir(parents=True, exist_ok=True)

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_target_not_a_file(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        with self._test(
            [], error_messages=("Cannot export vault settings:",)
        ) as command_line:
            dname = cli_helpers.config_filename(subsystem=None)
            command_line[:] = ["--export", os.fsdecode(dname), *export_options]

    @pytest_machinery.skip_if_on_the_annoying_os
    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_settings_directory_not_a_directory(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        with self._test(
            ["--export", "-", *export_options],
            error_messages=(
                "Cannot load vault settings:",
                "Cannot load user config:",
            ),
        ):
            config_dir = cli_helpers.config_filename(subsystem=None)
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree(config_dir)
            config_dir.write_text("Obstruction!!\n")


class TestNotesPrinting:
    """Tests concerning printing the service notes."""

    def _test(
        self,
        notes: str,
        /,
        notes_placement: Literal["before", "after"] | None = None,
        placement_args: list[str] | tuple[str, ...] = (),
    ) -> None:
        notes_stripped = notes.strip()
        maybe_notes = {"notes": notes_stripped} if notes_stripped else {}
        vault_config = {
            "global": {"phrase": DUMMY_PASSPHRASE},
            "services": {
                DUMMY_SERVICE: {**maybe_notes, **DUMMY_CONFIG_SETTINGS}
            },
        }
        result_phrase = DUMMY_RESULT_PASSPHRASE.decode("ascii")
        expected = (
            f"{notes_stripped}\n\n{result_phrase}\n"
            if notes_placement == "before"
            else f"{result_phrase}\n\n{notes_stripped}\n\n"
            if notes_placement == "after"
            else None
        )
        runner = machinery.CliRunner(mix_stderr=notes_placement is not None)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=vault_config,
                )
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [*placement_args, "--", DUMMY_SERVICE],
                catch_exceptions=False,
            )
            if expected is not None:
                assert result.clean_exit(output=expected), (
                    "expected clean exit"
                )
            else:
                assert result.clean_exit(), "expected clean exit"
                assert result.stdout, "expected program output"
                assert result.stdout.strip() == result_phrase, (
                    "expected known program output"
                )
                assert result.stderr or not notes_stripped, "expected stderr"
                assert "Error:" not in result.stderr, (
                    "expected no error messages on stderr"
                )
                assert result.stderr.strip() == notes_stripped, (
                    "expected known stderr contents"
                )

    @hypothesis.given(notes=Strategies.notes().filter(str.strip))
    def test_service_with_notes_actually_prints_notes(
        self,
        notes: str,
    ) -> None:
        """Service notes are printed, if they exist."""
        hypothesis.assume("Error:" not in notes)
        self._test(notes, notes_placement=None, placement_args=())

    @Parametrize.NOTES_PLACEMENT
    @hypothesis.given(notes=Strategies.notes().filter(str.strip))
    def test_notes_placement(
        self,
        notes_placement: Literal["before", "after"],
        placement_args: list[str],
        notes: str,
    ) -> None:
        self._test(
            notes,
            notes_placement=notes_placement,
            placement_args=placement_args,
        )


class TestNotesEditing:
    """Superclass for tests concerning editing service notes."""

    CURRENT_NOTES = "Contents go here"
    OLD_NOTES_TEXT = (
        "These backup notes are left over from the previous session."
    )

    def _calculate_expected_contents(
        self,
        final_notes: str,
        /,
        *,
        modern_editor_interface: bool,
        current_notes: str | None = CURRENT_NOTES,
        old_notes_text: str | None = OLD_NOTES_TEXT,
    ) -> tuple[str, str]:
        current_notes = current_notes or ""
        old_notes_text = old_notes_text or ""
        # For the modern editor interface, the notes change if and only
        # if the notes change to a different, non-empty string.  There
        # are no backup notes, so we return the old ones (which may be
        # synthetic) unchanged.
        if modern_editor_interface:
            return old_notes_text.strip(), (
                final_notes.strip()
                if final_notes.strip()
                and final_notes.strip() != current_notes.strip()
                else current_notes.strip()
            )
        # For the legacy editor interface, the notes and the backup
        # notes change if and only if the new notes differ from the
        # previous notes.
        return (
            (current_notes.strip(), final_notes.strip())
            if final_notes.strip() != current_notes.strip()
            else (old_notes_text.strip(), current_notes.strip())
        )

    def _test(
        self,
        edit_result: str,
        /,
        *,
        modern_editor_interface: bool,
        current_notes: str | None = CURRENT_NOTES,
        old_notes_text: str | None = OLD_NOTES_TEXT,
    ) -> tuple[machinery.ReadableResult, str, _types.VaultConfig]:
        if hypothesis.currently_in_test_context():  # pragma: no branch
            hypothesis.note(f"{edit_result = }")
            hypothesis.note(f"{modern_editor_interface = }")
            hypothesis.note(
                f"vault_config = {self._vault_config(current_notes or '')}"
            )
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=self._vault_config(current_notes or ""),
                )
            )
            notes_backup_file = cli_helpers.config_filename(
                subsystem="notes backup"
            )
            if old_notes_text and old_notes_text.strip():  # pragma: no branch
                notes_backup_file.write_text(
                    old_notes_text.strip(), encoding="UTF-8"
                )
            monkeypatch.setattr(click, "edit", lambda *_a, **_kw: edit_result)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    "--config",
                    "--notes",
                    "--modern-editor-interface"
                    if modern_editor_interface
                    else "--vault-legacy-editor-interface",
                    "--",
                    "sv",
                ],
                catch_exceptions=False,
            )
            backup_contents = notes_backup_file.read_text(encoding="UTF-8")
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config = json.load(infile)
            if hypothesis.currently_in_test_context():  # pragma: no branch
                hypothesis.note(f"{result = }")
                hypothesis.note(f"{backup_contents = }")
                hypothesis.note(f"{config = }")
            return result, backup_contents, config

    def _assert_noop_exit(
        self,
        result: machinery.ReadableResult,
        /,
        *,
        modern_editor_interface: bool = False,
    ) -> None:
        # We do not distinguish between aborts and no-op edits.  Aborts
        # are treated as failures (error exit), and thus tested
        # specifically in a different class.
        if modern_editor_interface:
            assert result.error_exit(
                error="the user aborted the request"
            ) or result.clean_exit(empty_stderr=True), "expected clean exit"
        else:
            assert result.clean_exit(empty_stderr=False), "expected clean exit"

    def _assert_normal_exit(self, result: machinery.ReadableResult) -> None:
        assert result.clean_exit(), "expected clean exit"
        assert all(map(is_warning_line, result.stderr.splitlines(True)))

    def _assert_notes_backup_warning(
        self,
        caplog: pytest.LogCaptureFixture,
        /,
        *,
        modern_editor_interface: bool,
        notes_unchanged: bool = False,
    ) -> None:
        assert (
            modern_editor_interface
            or notes_unchanged
            or machinery.warning_emitted(
                "A backup copy of the old notes was saved",
                caplog.record_tuples,
            )
        ), "expected known warning message on stderr"

    def _assert_notes_and_backup_notes(
        self,
        /,
        *,
        final_notes: str,
        new_backup_notes: str,
        new_config: _types.VaultConfig,
        modern_editor_interface: bool,
        current_notes: str | None = CURRENT_NOTES,
        old_notes_text: str | None = OLD_NOTES_TEXT,
    ) -> None:
        if hypothesis.currently_in_test_context():  # pragma: no branch
            hypothesis.note(f"{final_notes = }")
            hypothesis.note(f"{current_notes = }")
        expected_backup_notes, expected_notes = (
            self._calculate_expected_contents(
                final_notes,
                modern_editor_interface=modern_editor_interface,
                current_notes=current_notes,
                old_notes_text=old_notes_text,
            )
        )
        expected_config = self._vault_config(expected_notes)
        assert new_config == expected_config
        assert new_backup_notes == expected_backup_notes

    @staticmethod
    def _vault_config(
        starting_notes: str = CURRENT_NOTES, /
    ) -> _types.VaultConfig:
        return {
            "global": {"phrase": "abc"},
            "services": {
                "sv": {"notes": starting_notes.strip()}
                if starting_notes.strip()
                else {}
            },
        }

    class ExtraArgs(TypedDict):
        modern_editor_interface: bool
        current_notes: NotRequired[str]
        old_notes_text: NotRequired[str]


class TestNotesEditingValid(TestNotesEditing):
    """Tests concerning editing service notes: valid calls."""

    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(
        notes=Strategies.notes()
        .filter(str.strip)
        .filter(lambda notes: notes != TestNotesEditingValid.CURRENT_NOTES)
    )
    @hypothesis.example(TestNotesEditing.CURRENT_NOTES)
    def test_successful_edit(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Editing notes works."""
        # Reset caplog between hypothesis runs.
        caplog.clear()
        marker = cli_messages.TranslatedString(
            cli_messages.Label.DERIVEPASSPHRASE_VAULT_NOTES_MARKER
        )
        edit_result = (
            f"""

{marker}
{notes}
"""
            if modern_editor_interface
            else notes.strip()
        )

        extra_args: TestNotesEditing.ExtraArgs = {
            "modern_editor_interface": modern_editor_interface,
            "current_notes": self.CURRENT_NOTES,
            "old_notes_text": self.OLD_NOTES_TEXT,
        }
        notes_unchanged = notes.strip() == extra_args["current_notes"].strip()

        result, new_backup_notes, new_config = self._test(
            edit_result, **extra_args
        )
        self._assert_normal_exit(result)
        self._assert_notes_and_backup_notes(
            final_notes=notes,
            new_backup_notes=new_backup_notes,
            new_config=new_config,
            **extra_args,
        )
        self._assert_notes_backup_warning(
            caplog,
            modern_editor_interface=modern_editor_interface,
            notes_unchanged=notes_unchanged,
        )

    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(notes=Strategies.notes().filter(str.strip))
    @hypothesis.example(TestNotesEditing.CURRENT_NOTES)
    def test_noop_edit(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """No-op editing existing notes works.

        The notes are unchanged, and the command-line interface does not
        report an abort.  For the legacy editor interface, the backup
        notes are unchanged as well.

        """
        # Reset caplog between hypothesis runs.
        caplog.clear()
        marker = cli_messages.TranslatedString(
            cli_messages.Label.DERIVEPASSPHRASE_VAULT_NOTES_MARKER
        )
        edit_result = (f"{marker}\n" if modern_editor_interface else "") + (
            " " * 6 + notes + "\n" * 6
        )

        extra_args: TestNotesEditing.ExtraArgs = {
            "modern_editor_interface": modern_editor_interface,
            "current_notes": notes.strip(),
            "old_notes_text": self.OLD_NOTES_TEXT,
        }

        result, new_backup_notes, new_config = self._test(
            edit_result, **extra_args
        )
        self._assert_noop_exit(
            result,
            modern_editor_interface=modern_editor_interface,
        )
        self._assert_notes_and_backup_notes(
            final_notes=notes,
            new_backup_notes=new_backup_notes,
            new_config=new_config,
            **extra_args,
        )
        self._assert_notes_backup_warning(
            caplog,
            modern_editor_interface=modern_editor_interface,
            notes_unchanged=True,
        )

    # TODO(the-13th-letter): Keep this behavior or not, with or without
    # warning?
    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(notes=Strategies.notes().filter(str.strip))
    def test_marker_removed(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Removing the notes marker still saves the notes.

        TODO: Keep this behavior or not, with or without warning?

        """
        notes_marker = cli_messages.TranslatedString(
            cli_messages.Label.DERIVEPASSPHRASE_VAULT_NOTES_MARKER
        )
        hypothesis.assume(str(notes_marker) not in notes.strip())
        # Reset caplog between hypothesis runs.
        caplog.clear()

        extra_args: TestNotesEditing.ExtraArgs = {
            "modern_editor_interface": modern_editor_interface,
            "current_notes": self.CURRENT_NOTES,
            "old_notes_text": self.OLD_NOTES_TEXT,
        }
        notes_unchanged = notes.strip() == extra_args["current_notes"].strip()

        result, new_backup_notes, new_config = self._test(
            notes.strip(), **extra_args
        )
        self._assert_normal_exit(result)
        self._assert_notes_and_backup_notes(
            final_notes=notes,
            new_backup_notes=new_backup_notes,
            new_config=new_config,
            **extra_args,
        )
        self._assert_notes_backup_warning(
            caplog,
            modern_editor_interface=modern_editor_interface,
            notes_unchanged=notes_unchanged,
        )


class TestNotesEditingInvalid(TestNotesEditing):
    """Tests concerning editing service notes: invalid/error calls."""

    @hypothesis.given(notes=Strategies.notes())
    @hypothesis.example("")
    def test_abort(
        self,
        notes: str,
    ) -> None:
        """Aborting editing notes works, even if no notes are stored yet.

        Aborting is only supported with the modern editor interface.

        """
        edit_result = ""

        extra_args: TestNotesEditing.ExtraArgs = {
            "modern_editor_interface": True,
            "current_notes": notes.strip(),
            "old_notes_text": self.OLD_NOTES_TEXT,
        }

        result, new_backup_notes, new_config = self._test(
            edit_result, **extra_args
        )
        assert result.error_exit(error="the user aborted the request"), (
            "expected error exit"
        )
        self._assert_notes_and_backup_notes(
            final_notes=notes.strip(),
            new_backup_notes=new_backup_notes,
            new_config=new_config,
            **extra_args,
        )

    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(notes=Strategies.notes())
    @hypothesis.example("")
    def test_fail_on_config_option_missing(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Editing notes fails (and warns) if `--config` is missing."""
        maybe_notes = {"notes": notes.strip()} if notes.strip() else {}
        vault_config = {
            "global": {"phrase": DUMMY_PASSPHRASE},
            "services": {
                DUMMY_SERVICE: {**maybe_notes, **DUMMY_CONFIG_SETTINGS}
            },
        }
        old_notes_text = (
            "These backup notes are left over from the previous session."
        )
        # Reset caplog between hypothesis runs.
        caplog.clear()
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=vault_config,
                )
            )
            EDIT_ATTEMPTED = "edit attempted!"  # noqa: N806

            def raiser(*_args: Any, **_kwargs: Any) -> NoReturn:
                pytest.fail(EDIT_ATTEMPTED)

            notes_backup_file = cli_helpers.config_filename(
                subsystem="notes backup"
            )
            notes_backup_file.write_text(old_notes_text, encoding="UTF-8")
            monkeypatch.setattr(click, "edit", raiser)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    "--notes",
                    "--modern-editor-interface"
                    if modern_editor_interface
                    else "--vault-legacy-editor-interface",
                    "--",
                    DUMMY_SERVICE,
                ],
                catch_exceptions=False,
            )
            assert result.clean_exit(
                output=DUMMY_RESULT_PASSPHRASE.decode("ascii")
            ), "expected clean exit"
            assert result.stderr
            assert notes.strip() in result.stderr
            assert all(
                is_warning_line(line)
                for line in result.stderr.splitlines(True)
                if line.startswith(f"{cli.PROG_NAME}: ")
            )
            assert machinery.warning_emitted(
                "Specifying --notes without --config is ineffective.  "
                "No notes will be edited.",
                caplog.record_tuples,
            ), "expected known warning message in stderr"
            assert (
                modern_editor_interface
                or notes_backup_file.read_text(encoding="UTF-8")
                == old_notes_text
            )
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config = json.load(infile)
            assert config == vault_config


class TestStoringConfigurationSuccesses:
    """Tests concerning storing the configuration: successes."""

    def _test(
        self,
        command_line: list[str],
        /,
        *,
        starting_config: _types.VaultConfig | None,
        result_config: _types.VaultConfig,
        input: str | bytes | None = None,
    ) -> machinery.ReadableResult:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=starting_config,
                )
            )
            if starting_config is None:
                with contextlib.suppress(FileNotFoundError):
                    shutil.rmtree(cli_helpers.config_filename(subsystem=None))
            monkeypatch.setattr(
                cli_helpers,
                "get_suitable_ssh_keys",
                callables.suitable_ssh_keys,
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--config", *command_line],
                catch_exceptions=False,
                input=input,
            )
            assert result.clean_exit(), "expected clean exit"
            config_txt = cli_helpers.config_filename(
                subsystem="vault"
            ).read_text(encoding="UTF-8")
            config = json.loads(config_txt)
            assert config == result_config, (
                "stored config does not match expectation"
            )
            assert_vault_config_is_indented_and_line_broken(config_txt)
            return result

    @Parametrize.CONFIG_EDITING_VIA_CONFIG_FLAG
    def test_store_good_config(
        self,
        command_line: list[str],
        input: str,
        starting_config: Any,
        result_config: Any,
    ) -> None:
        """Storing valid settings via `--config` works.

        The format also contains embedded newlines and indentation to make
        the config more readable.

        """
        self._test(
            command_line,
            input=input,
            starting_config=starting_config,
            result_config=result_config,
        )

    def test_config_directory_nonexistant(
        self,
    ) -> None:
        """Running without an existing config directory works.

        This is a regression test; see [the "pretty-print-json"
        issue][PRETTY_PRINT_JSON] for context.  See also
        [TestStoringConfigurationFailures.test_config_directory_not_a_file][]
        for a related aspect of this.

        [PRETTY_PRINT_JSON]: https://the13thletter.info/derivepassphrase/0.x/wishlist/pretty-print-json/

        """
        result = self._test(
            ["-p"],
            starting_config=None,
            result_config={"global": {"phrase": "abc"}, "services": {}},
            input="abc\n",
        )
        assert result.stderr == "Passphrase:", "program unexpectedly failed?!"


class TestStoringConfigurationFailures:
    """Tests concerning storing the configuration: failures."""

    @contextlib.contextmanager
    def _test(
        self,
        command_line: list[str],
        error_text: str,
        input: str | bytes | None = None,
        starting_config: _types.VaultConfig = {  # noqa: B006
            "global": {"phrase": "abc"},
            "services": {},
        },
        patch_suitable_ssh_keys: bool = True,
    ) -> Iterator[pytest.MonkeyPatch]:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=starting_config,
                )
            )
            # Patch the list of suitable SSH keys by default, lest we be
            # at the mercy of whatever SSH agent may be running. (But
            # allow a test to turn this off, if it would interfere with
            # the testing target, e.g. because we are testing
            # non-reachability of the agent.)
            if patch_suitable_ssh_keys:
                monkeypatch.setattr(
                    cli_helpers,
                    "get_suitable_ssh_keys",
                    callables.suitable_ssh_keys,
                )
            yield monkeypatch
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--config", *command_line],
                catch_exceptions=False,
                input=input,
            )
        assert result.error_exit(error=error_text), (
            "expected error exit and known error message"
        )

    @Parametrize.CONFIG_EDITING_VIA_CONFIG_FLAG_FAILURES
    def test_store_bad_config(
        self,
        command_line: list[str],
        input: str,
        err_text: str,
    ) -> None:
        """Storing invalid settings via `--config` fails."""
        with self._test(command_line, error_text=err_text, input=input):
            pass

    def test_fail_because_no_ssh_key_selection(self) -> None:
        """Not selecting an SSH key during `--config --key` fails.

        (This test does not actually need a running agent; the agent's
        response is mocked by the test harness.)

        """
        with self._test(
            ["--key"], error_text="the user aborted the request"
        ) as monkeypatch:

            def prompt_for_selection(*_args: Any, **_kwargs: Any) -> NoReturn:
                raise IndexError(cli_helpers.EMPTY_SELECTION)

            monkeypatch.setattr(
                cli_helpers, "prompt_for_selection", prompt_for_selection
            )

    def test_fail_because_no_ssh_agent(self) -> None:
        """Not running an SSH agent during `--config --key` fails.

        (This test does not actually need a running agent; the agent's
        response is mocked by the test harness.)

        """
        with self._test(
            ["--key"],
            error_text="Cannot find any running SSH agent",
            patch_suitable_ssh_keys=False,
        ) as monkeypatch:
            monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

    def test_fail_because_bad_ssh_agent_connection(self) -> None:
        """Not running a reachable SSH agent during `--config --key` fails.

        (This test does not actually need a running agent; the agent's
        response is mocked by the test harness.)

        """
        with self._test(
            ["--key"],
            error_text="Cannot connect to the SSH agent",
            patch_suitable_ssh_keys=False,
        ) as monkeypatch:
            cwd = pathlib.Path.cwd().resolve()
            monkeypatch.setenv("SSH_AUTH_SOCK", str(cwd))

    @Parametrize.TRY_RACE_FREE_IMPLEMENTATION
    def test_fail_because_read_only_file(
        self, try_race_free_implementation: bool
    ) -> None:
        """Using a read-only configuration file with `--config` fails."""
        with self._test(
            ["--length=15", "--", DUMMY_SERVICE],
            error_text="Cannot store vault settings:",
        ):
            callables.make_file_readonly(
                cli_helpers.config_filename(subsystem="vault"),
                try_race_free_implementation=try_race_free_implementation,
            )

    def test_fail_because_of_custom_error(self) -> None:
        """Triggering internal errors during `--config` leads to failure."""
        custom_error = "custom error message"
        with self._test(
            ["--length=15", "--", DUMMY_SERVICE], error_text=custom_error
        ) as monkeypatch:

            def raiser(config: Any) -> None:
                del config
                raise RuntimeError(custom_error)

            monkeypatch.setattr(cli_helpers, "save_config", raiser)

    def test_fail_because_unsetting_and_setting_same_settings(self) -> None:
        """Issuing conflicting settings to `--config` fails."""
        with self._test(
            ["--unset=length", "--length=15", "--", DUMMY_SERVICE],
            error_text="Attempted to unset and set --length at the same time.",
        ):
            pass

    def test_fail_because_ssh_agent_has_no_keys_loaded(self) -> None:
        """Not holding any SSH keys during `--config --key` fails.

        (This test does not actually need a running agent; the agent's
        response is mocked by the test harness.)

        """
        with self._test(
            ["--key"],
            error_text="no keys suitable",
            patch_suitable_ssh_keys=False,
        ) as monkeypatch:

            def func(
                *_args: Any,
                **_kwargs: Any,
            ) -> list[_types.SSHKeyCommentPair]:
                return []

            monkeypatch.setattr(ssh_agent.SSHAgentClient, "list_keys", func)

    def test_store_config_fail_manual_ssh_agent_runtime_error(self) -> None:
        """Triggering an error in the SSH agent during `--config --key` leads to failure.

        (This test does not actually need a running agent; the agent's
        response is mocked by the test harness.)

        """
        with self._test(
            ["--key"],
            error_text="violates the communication protocol",
            patch_suitable_ssh_keys=False,
        ) as monkeypatch:

            def raiser(*_args: Any, **_kwargs: Any) -> None:
                raise ssh_agent.TrailingDataError()

            monkeypatch.setattr(ssh_agent.SSHAgentClient, "list_keys", raiser)

    def test_store_config_fail_manual_ssh_agent_refuses(self) -> None:
        """The SSH agent refusing during `--config --key` leads to failure.

        (This test does not actually need a running agent; the agent's
        response is mocked by the test harness.)

        """
        with self._test(
            ["--key"], error_text="refused to", patch_suitable_ssh_keys=False
        ) as monkeypatch:

            def func(*_args: Any, **_kwargs: Any) -> NoReturn:
                raise ssh_agent.SSHAgentFailedError(
                    _types.SSH_AGENT.FAILURE, b""
                )

            monkeypatch.setattr(ssh_agent.SSHAgentClient, "list_keys", func)

    def test_config_directory_not_a_file(self) -> None:
        """Erroring without an existing config directory errors normally.

        That is, the missing configuration directory does not cause any
        errors by itself.

        This is a regression test; see [the "pretty-print-json"
        issue][PRETTY_PRINT_JSON] for context.  See also
        [TestStoringConfigurationSuccesses.test_config_directory_nonexistant][]
        for a related aspect of this.

        [PRETTY_PRINT_JSON]: https://the13thletter.info/derivepassphrase/0.x/wishlist/pretty-print-json/

        """
        with self._test(
            ["--phrase"],
            error_text="Cannot store vault settings:",
            input="abc\n",
        ) as monkeypatch:
            save_config_ = cli_helpers.save_config

            def obstruct_config_saving(*args: Any, **kwargs: Any) -> Any:
                config_dir = cli_helpers.config_filename(subsystem=None)
                with contextlib.suppress(FileNotFoundError):
                    shutil.rmtree(config_dir)
                config_dir.write_text("Obstruction!!\n")
                monkeypatch.setattr(cli_helpers, "save_config", save_config_)
                return save_config_(*args, **kwargs)

            monkeypatch.setattr(
                cli_helpers, "save_config", obstruct_config_saving
            )


class TestPassphraseUnicodeNormalization:
    """Tests concerning the Unicode normalization of passphrases."""

    DEFAULT_VAULT_CONFIG: ClassVar[_types.VaultConfig] = {
        "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()}
    }

    def _test(
        self,
        command_line: list[str],
        /,
        *,
        main_config: str,
        message: str,
        caplog: pytest.LogCaptureFixture | None = None,
        input: str | None = None,
    ) -> None:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=self.DEFAULT_VAULT_CONFIG,
                    main_config_str=main_config,
                )
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--debug", *command_line]
                if caplog is not None
                else command_line,
                catch_exceptions=False,
                input=input,
            )
        if caplog is not None:
            assert result.clean_exit(), "expected clean exit"
            assert machinery.warning_emitted(message, caplog.record_tuples), (
                "expected known warning message in stderr"
            )
        else:
            assert result.error_exit(
                error="The user configuration file is invalid."
            ), "expected error exit and known error message"
            assert result.error_exit(error=message), (
                "expected error exit and known error message"
            )

    @Parametrize.UNICODE_NORMALIZATION_WARNING_INPUTS
    def test_warning(
        self,
        caplog: pytest.LogCaptureFixture,
        main_config: str,
        command_line: list[str],
        input: str | None,
        warning_message: str,
    ) -> None:
        """Using unnormalized Unicode passphrases warns."""
        self._test(
            command_line,
            main_config=main_config,
            message=warning_message,
            caplog=caplog,
            input=input,
        )

    @Parametrize.UNICODE_NORMALIZATION_ERROR_INPUTS
    def test_error(
        self,
        main_config: str,
        command_line: list[str],
        input: str | None,
        error_message: str,
    ) -> None:
        """Using unknown Unicode normalization forms fails."""
        self._test(
            command_line,
            main_config=main_config,
            message=error_message,
            input=input,
        )


class TestUserConfigurationFileOther:
    """Other tests concerning the user configuration file."""

    @contextlib.contextmanager
    def _test(
        self,
        *,
        main_config: str = "",
    ) -> Iterator[pytest.MonkeyPatch]:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={"services": {}},
                    main_config_str=main_config,
                )
            )
            yield monkeypatch
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--phrase", "--", DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            assert result.error_exit(error="Cannot load user config:"), (
                "expected error exit and known error message"
            )

    def test_bad_user_config_file(
        self,
    ) -> None:
        """Loading a user configuration file in an invalid format fails."""
        with self._test(main_config="This file is not valid TOML.\n"):
            pass

    def test_user_config_is_a_directory(
        self,
    ) -> None:
        """Loading a user configuration non-file fails."""
        with self._test():
            user_config = cli_helpers.config_filename(
                subsystem="user configuration"
            )
            user_config.unlink()
            user_config.mkdir(parents=True, exist_ok=True)


class TestSSHAgentAvailability:
    """Tests concerning the availability of the SSH agent."""

    def test_missing_af_unix_support(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Querying the SSH agent without `AF_UNIX` support fails."""
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={"global": {"phrase": "abc"}, "services": {}},
                )
            )
            monkeypatch.setenv(
                "SSH_AUTH_SOCK", "the value doesn't even matter"
            )
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, "SOCKET_PROVIDERS", ["posix"]
            )
            monkeypatch.delattr(socket, "AF_UNIX", raising=False)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--key", "--config"],
                catch_exceptions=False,
            )
        assert result.error_exit(
            error="does not support communicating with it"
        ), "expected error exit and known error message"
        assert machinery.warning_emitted(
            "Cannot connect to an SSH agent via UNIX domain sockets",
            caplog.record_tuples,
        ), "expected known warning message in stderr"
