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
from typing import TYPE_CHECKING

import click.testing
import hypothesis
import pytest
from hypothesis import strategies
from typing_extensions import Any, NamedTuple

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
    from typing import NoReturn

    from typing_extensions import Literal

DUMMY_SERVICE = data.DUMMY_SERVICE
DUMMY_PASSPHRASE = data.DUMMY_PASSPHRASE
DUMMY_CONFIG_SETTINGS = data.DUMMY_CONFIG_SETTINGS
DUMMY_RESULT_PASSPHRASE = data.DUMMY_RESULT_PASSPHRASE
DUMMY_RESULT_KEY1 = data.DUMMY_RESULT_KEY1
DUMMY_PHRASE_FROM_KEY1_RAW = data.DUMMY_PHRASE_FROM_KEY1_RAW
DUMMY_PHRASE_FROM_KEY1 = data.DUMMY_PHRASE_FROM_KEY1

DUMMY_KEY1 = data.DUMMY_KEY1
DUMMY_KEY1_B64 = data.DUMMY_KEY1_B64
DUMMY_KEY2 = data.DUMMY_KEY2
DUMMY_KEY2_B64 = data.DUMMY_KEY2_B64
DUMMY_KEY3 = data.DUMMY_KEY3
DUMMY_KEY3_B64 = data.DUMMY_KEY3_B64

TEST_CONFIGS = data.TEST_CONFIGS


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


class Parametrize(types.SimpleNamespace):
    """Common test parametrizations."""

    AUTO_PROMPT = pytest.mark.parametrize(
        "auto_prompt", [False, True], ids=["normal_prompt", "auto_prompt"]
    )
    CHARSET_NAME = pytest.mark.parametrize(
        "charset_name", ["lower", "upper", "number", "space", "dash", "symbol"]
    )
    UNICODE_NORMALIZATION_COMMAND_LINES = pytest.mark.parametrize(
        "command_line",
        [
            pytest.param(
                ["--config", "--phrase"],
                id="configure global passphrase",
            ),
            pytest.param(
                ["--config", "--phrase", "--", "DUMMY_SERVICE"],
                id="configure service passphrase",
            ),
            pytest.param(
                ["--phrase", "--", DUMMY_SERVICE],
                id="interactive passphrase",
            ),
        ],
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
        ["command_line", "input", "result_config"],
        [
            pytest.param(
                ["--phrase"],
                "my passphrase\n",
                {"global": {"phrase": "my passphrase"}, "services": {}},
                id="phrase",
            ),
            pytest.param(
                ["--key"],
                "1\n",
                {
                    "global": {"key": DUMMY_KEY1_B64, "phrase": "abc"},
                    "services": {},
                },
                id="key",
            ),
            pytest.param(
                ["--phrase", "--", "sv"],
                "my passphrase\n",
                {
                    "global": {"phrase": "abc"},
                    "services": {"sv": {"phrase": "my passphrase"}},
                },
                id="phrase-sv",
            ),
            pytest.param(
                ["--key", "--", "sv"],
                "1\n",
                {
                    "global": {"phrase": "abc"},
                    "services": {"sv": {"key": DUMMY_KEY1_B64}},
                },
                id="key-sv",
            ),
            pytest.param(
                ["--key", "--length", "15", "--", "sv"],
                "1\n",
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
        [conf.config for conf in TEST_CONFIGS if conf.is_valid()],
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
    NOOP_EDIT_FUNCS = pytest.mark.parametrize(
        ["edit_func_name", "modern_editor_interface"],
        [
            pytest.param("empty", True, id="empty"),
            pytest.param("space", False, id="space-legacy"),
            pytest.param("space", True, id="space-modern"),
        ],
    )
    EXPORT_FORMAT_OPTIONS = pytest.mark.parametrize(
        "export_options",
        [
            [],
            ["--export-as=sh"],
        ],
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
        "try_race_free_implementation", [True, False]
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

    @Parametrize.CHARSET_NAME
    def test_disable_character_set(
        self,
        charset_name: str,
    ) -> None:
        """Named character classes can be disabled on the command-line."""
        option = f"--{charset_name}"
        charset = vault.Vault.CHARSETS[charset_name].decode("ascii")
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [option, "0", "-p", "--", DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), "expected clean exit:"
        for c in charset:
            assert c not in result.stdout, (
                f"derived password contains forbidden character {c!r}"
            )

    def test_disable_repetition(
        self,
    ) -> None:
        """Character repetition can be disabled on the command-line."""
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--repeat", "0", "-p", "--", DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
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

    @Parametrize.CONFIG_WITH_PHRASE
    def test_phrase_from_config(
        self,
        config: _types.VaultConfig,
    ) -> None:
        """A stored configured master passphrase will be used."""
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--", DUMMY_SERVICE],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), (
            "expected clean exit and empty stderr"
        )
        assert result.stdout
        assert (
            result.stdout.rstrip("\n").encode("UTF-8")
            == DUMMY_RESULT_PASSPHRASE
        ), "expected known output"

    @Parametrize.AUTO_PROMPT
    def test_phrase_from_command_line(
        self,
        auto_prompt: bool,
    ) -> None:
        """A master passphrase requested on the command-line will be used."""
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
                    vault_config={
                        "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}
                    },
                )
            )
            if auto_prompt:
                monkeypatch.setattr(
                    cli_helpers,
                    "prompt_for_passphrase",
                    callables.auto_prompt,
                )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["-p", "--", DUMMY_SERVICE],
                input=None if auto_prompt else DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        assert result.clean_exit(), "expected clean exit"
        assert result.stdout, "expected program output"
        last_line = result.stdout.splitlines(True)[-1]
        assert (
            last_line.rstrip("\n").encode("UTF-8") == DUMMY_RESULT_PASSPHRASE
        ), "expected known output"


class TestKeyBasic:
    """Tests for SSH key configuration: basic."""

    @Parametrize.CONFIG_WITH_KEY
    def test_key_from_config(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
        config: _types.VaultConfig,
    ) -> None:
        """A stored configured SSH key will be used."""
        del running_ssh_agent
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
                vault.Vault,
                "phrase_from_key",
                callables.phrase_from_key,
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--", DUMMY_SERVICE],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), (
            "expected clean exit and empty stderr"
        )
        assert result.stdout
        assert (
            result.stdout.rstrip("\n").encode("UTF-8")
            != DUMMY_RESULT_PASSPHRASE
        ), "known false output: phrase-based instead of key-based"
        assert (
            result.stdout.rstrip("\n").encode("UTF-8") == DUMMY_RESULT_KEY1
        ), "expected known output"

    def test_key_from_command_line(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
    ) -> None:
        """An SSH key requested on the command-line will be used."""
        del running_ssh_agent
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
                    vault_config={
                        "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}
                    },
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
                ["-k", "--", DUMMY_SERVICE],
                input="1\n",
                catch_exceptions=False,
            )
        assert result.clean_exit(), "expected clean exit"
        assert result.stdout, "expected program output"
        last_line = result.stdout.splitlines(True)[-1]
        assert (
            last_line.rstrip("\n").encode("UTF-8") != DUMMY_RESULT_PASSPHRASE
        ), "known false output: phrase-based instead of key-based"
        assert last_line.rstrip("\n").encode("UTF-8") == DUMMY_RESULT_KEY1, (
            "expected known output"
        )


class TestPhraseAndKeyOverriding:
    """Tests for master passphrase and SSH key configuration: overriding."""

    @Parametrize.BASE_CONFIG_WITH_KEY_VARIATIONS
    @Parametrize.KEY_INDEX
    def test_key_override_on_command_line(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
        config: dict[str, Any],
        key_index: int,
    ) -> None:
        """A command-line SSH key will override the configured key."""
        del running_ssh_agent
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
                ["-k", "--", DUMMY_SERVICE],
                input=f"{key_index}\n",
            )
        assert result.clean_exit(), "expected clean exit"
        assert result.stdout, "expected program output"
        assert result.stderr, "expected stderr"
        assert "Error:" not in result.stderr, (
            "expected no error messages on stderr"
        )

    def test_service_phrase_if_key_in_global_config(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
    ) -> None:
        """A command-line passphrase will override the configured key."""
        del running_ssh_agent
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
                    vault_config={
                        "global": {"key": DUMMY_KEY1_B64},
                        "services": {
                            DUMMY_SERVICE: {
                                "phrase": DUMMY_PASSPHRASE.rstrip("\n"),
                                **DUMMY_CONFIG_SETTINGS,
                            }
                        },
                    },
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
                ["--", DUMMY_SERVICE],
                catch_exceptions=False,
            )
        assert result.clean_exit(), "expected clean exit"
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
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        assert result.clean_exit(), "expected clean exit"
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

    @Parametrize.VAULT_CHARSET_OPTION
    def test_invalid_argument_range(
        self,
        option: str,
    ) -> None:
        """Requesting invalidly many characters from a class fails."""
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
            monkeypatch.setattr(
                cli_helpers,
                "prompt_for_passphrase",
                callables.auto_prompt,
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                options if service else [*options, "--", DUMMY_SERVICE],
                input=input,
                catch_exceptions=False,
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
            else:
                assert result.clean_exit(empty_stderr=True), (
                    "expected clean exit"
                )
        if check_success:
            # TODO(the-13th-letter): Rewrite using parenthesized
            # with-statements.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
            with contextlib.ExitStack() as stack:
                monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
                stack.enter_context(
                    pytest_machinery.isolated_vault_config(
                        monkeypatch=monkeypatch,
                        runner=runner,
                        vault_config={
                            "global": {"phrase": "abc"},
                            "services": {},
                        },
                    )
                )
                monkeypatch.setattr(
                    cli_helpers,
                    "prompt_for_passphrase",
                    callables.auto_prompt,
                )
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    [*options, "--", DUMMY_SERVICE] if service else options,
                    input=input,
                    catch_exceptions=False,
                )
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
            monkeypatch.setattr(
                cli_helpers,
                "prompt_for_passphrase",
                callables.auto_prompt,
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--config", "--length=30", "--", ""],
                catch_exceptions=False,
            )
            assert result.clean_exit(empty_stderr=False), "expected clean exit"
            assert result.stderr is not None, "expected known error output"
            assert all(map(is_expected_warning, caplog.record_tuples)), (
                "expected known error output"
            )
            assert cli_helpers.load_config() == {
                "global": {"length": 30},
                "services": {},
            }, "requested configuration change was not applied"
            caplog.clear()
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--import", "-"],
                input=json.dumps({"services": {"": {"length": 40}}}),
                catch_exceptions=False,
            )
            assert result.clean_exit(empty_stderr=False), "expected clean exit"
            assert result.stderr is not None, "expected known error output"
            assert all(map(is_expected_warning, caplog.record_tuples)), (
                "expected known error output"
            )
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
                [*options, "--", DUMMY_SERVICE] if service else options,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        assert result.error_exit(error="mutually exclusive with "), (
            "expected error exit and known error message"
        )

    def test_no_arguments(self) -> None:
        """Calling `derivepassphrase vault` without any arguments fails."""
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
                cli.derivepassphrase_vault, [], catch_exceptions=False
            )
        assert result.error_exit(
            error="Deriving a passphrase requires a SERVICE"
        ), "expected error exit and known error message"

    def test_no_passphrase_or_key(
        self,
    ) -> None:
        """Deriving a passphrase without a passphrase or key fails."""
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
                ["--", DUMMY_SERVICE],
                catch_exceptions=False,
            )
        assert result.error_exit(error="No passphrase or key was given"), (
            "expected error exit and known error message"
        )


class TestImportConfigValid:
    """Tests concerning `vault` configuration imports: valid imports."""

    @Parametrize.VALID_TEST_CONFIGS
    def test_import_config(
        self,
        caplog: pytest.LogCaptureFixture,
        config: Any,
    ) -> None:
        """Importing a configuration works."""
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
            config2 = json.loads(config_txt)
        assert result.clean_exit(empty_stderr=False), "expected clean exit"
        assert config2 == config, "config not imported correctly"
        assert not result.stderr or all(  # pragma: no branch
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), "unexpected error output"
        assert_vault_config_is_indented_and_line_broken(config_txt)

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
    def test_import_smudged_config(
        self,
        caplog: pytest.LogCaptureFixture,
        conf: data.VaultTestConfig,
    ) -> None:
        """Importing a smudged configuration works.

        Tested via hypothesis.

        """
        config = conf.config
        config2 = copy.deepcopy(config)
        _types.clean_up_falsy_vault_config_values(config2)
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


class TestImportConfigInvalid:
    """Tests concerning `vault` configuration imports: invalid imports."""

    def test_import_config_not_a_vault_config(
        self,
    ) -> None:
        """Importing an invalid config fails."""
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
                ["--import", "-"],
                input="null",
                catch_exceptions=False,
            )
        assert result.error_exit(error="Invalid vault config"), (
            "expected error exit and known error message"
        )

    def test_import_config_not_json_data(
        self,
    ) -> None:
        """Importing an invalid config fails."""
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
                ["--import", "-"],
                input="This string is not valid JSON.",
                catch_exceptions=False,
            )
        assert result.error_exit(error="cannot decode JSON"), (
            "expected error exit and known error message"
        )

    def test_import_config_not_a_file(
        self,
    ) -> None:
        """Importing an invalid config fails."""
        runner = machinery.CliRunner(mix_stderr=False)
        # `isolated_vault_config` ensures the configuration is valid
        # JSON.  So, to pass an actual broken configuration, we must
        # open the configuration file ourselves afterwards, inside the
        # context.
        #
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

    @Parametrize.VALID_TEST_CONFIGS
    def test_export_config_success(
        self,
        caplog: pytest.LogCaptureFixture,
        config: Any,
    ) -> None:
        """Exporting a configuration works."""
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
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config2 = json.load(infile)
        assert result.clean_exit(empty_stderr=False), "expected clean exit"
        assert config2 == config, "config not imported correctly"
        assert not result.stderr or all(  # pragma: no branch
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), "unexpected error output"
        assert_vault_config_is_indented_and_line_broken(result.stdout)

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
        config = conf.config
        config2 = copy.deepcopy(config)
        _types.clean_up_falsy_vault_config_values(config2)
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
                    vault_config={"services": {}},
                )
            )
            result1 = runner.invoke(
                cli.derivepassphrase_vault,
                ["--import", "-"],
                input=json.dumps(config),
                catch_exceptions=False,
            )
            assert result1.clean_exit(empty_stderr=False), (
                "expected clean exit"
            )
            assert not result1.stderr or all(
                map(is_harmless_config_import_warning, caplog.record_tuples)
            ), "unexpected error output"
            result2 = runner.invoke(
                cli.derivepassphrase_vault,
                ["--export", "-"],
                catch_exceptions=False,
            )
            assert result2.clean_exit(empty_stderr=False), (
                "expected clean exit"
            )
            assert not result2.stderr or all(
                map(is_harmless_config_import_warning, caplog.record_tuples)
            ), "unexpected error output"
            config3 = json.loads(result2.stdout)
            assert config3 == config2, "config not exported correctly"

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_export_config_no_stored_settings(
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


class TestExportConfigInvalid:
    """Tests concerning `vault` configuration exports: invalid exports."""

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_export_config_bad_stored_config(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
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
                    vault_config={},
                )
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--export", "-", *export_options],
                input="null",
                catch_exceptions=False,
            )
        assert result.error_exit(error="Cannot load vault settings:"), (
            "expected error exit and known error message"
        )

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_export_config_not_a_file(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
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
            config_file = cli_helpers.config_filename(subsystem="vault")
            config_file.unlink(missing_ok=True)
            config_file.mkdir(parents=True, exist_ok=True)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--export", "-", *export_options],
                input="null",
                catch_exceptions=False,
            )
        assert result.error_exit(error="Cannot load vault settings:"), (
            "expected error exit and known error message"
        )

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_export_config_target_not_a_file(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
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
            dname = cli_helpers.config_filename(subsystem=None)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--export", os.fsdecode(dname), *export_options],
                input="null",
                catch_exceptions=False,
            )
        assert result.error_exit(error="Cannot export vault settings:"), (
            "expected error exit and known error message"
        )

    @pytest_machinery.skip_if_on_the_annoying_os
    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_export_config_settings_directory_not_a_directory(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
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
            config_dir = cli_helpers.config_filename(subsystem=None)
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree(config_dir)
            config_dir.write_text("Obstruction!!\n")
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--export", "-", *export_options],
                input="null",
                catch_exceptions=False,
            )
        assert result.error_exit(
            error="Cannot load vault settings:"
        ) or result.error_exit(error="Cannot load user config:"), (
            "expected error exit and known error message"
        )


class TestNotesPrinting:
    """Tests concerning printing the service notes."""

    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32,
                max_codepoint=126,
                include_characters="\n",
            ),
            max_size=256,
        ),
    )
    def test_service_with_notes_actually_prints_notes(
        self,
        notes: str,
    ) -> None:
        """Service notes are printed, if they exist."""
        hypothesis.assume("Error:" not in notes)
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
                    vault_config={
                        "global": {
                            "phrase": DUMMY_PASSPHRASE,
                        },
                        "services": {
                            DUMMY_SERVICE: {
                                "notes": notes,
                                **DUMMY_CONFIG_SETTINGS,
                            },
                        },
                    },
                )
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--", DUMMY_SERVICE],
            )
        assert result.clean_exit(), "expected clean exit"
        assert result.stdout, "expected program output"
        assert result.stdout.strip() == DUMMY_RESULT_PASSPHRASE.decode(
            "ascii"
        ), "expected known program output"
        assert result.stderr or not notes.strip(), "expected stderr"
        assert "Error:" not in result.stderr, (
            "expected no error messages on stderr"
        )
        assert result.stderr.strip() == notes.strip(), (
            "expected known stderr contents"
        )

    @Parametrize.NOTES_PLACEMENT
    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters="\n"
            ),
            min_size=1,
            max_size=512,
        ).filter(str.strip),
    )
    def test_notes_placement(
        self,
        notes_placement: Literal["before", "after"],
        placement_args: list[str],
        notes: str,
    ) -> None:
        notes = notes.strip()
        maybe_notes = {"notes": notes} if notes else {}
        vault_config = {
            "global": {"phrase": DUMMY_PASSPHRASE},
            "services": {
                DUMMY_SERVICE: {**maybe_notes, **DUMMY_CONFIG_SETTINGS}
            },
        }
        result_phrase = DUMMY_RESULT_PASSPHRASE.decode("ascii")
        expected = (
            f"{notes}\n\n{result_phrase}\n"
            if notes_placement == "before"
            else f"{result_phrase}\n\n{notes}\n\n"
        )
        runner = machinery.CliRunner(mix_stderr=True)
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
            assert result.clean_exit(output=expected), "expected clean exit"


class TestNotesEditingValid:
    """Tests concerning editing service notes: valid calls."""

    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters="\n"
            ),
            min_size=1,
            max_size=512,
        ).filter(str.strip),
    )
    def test_successful_edit(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Editing notes works."""
        marker = cli_messages.TranslatedString(
            cli_messages.Label.DERIVEPASSPHRASE_VAULT_NOTES_MARKER
        )
        edit_result = f"""

{marker}
{notes}
"""
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
                    vault_config={
                        "global": {"phrase": "abc"},
                        "services": {"sv": {"notes": "Contents go here"}},
                    },
                )
            )
            notes_backup_file = cli_helpers.config_filename(
                subsystem="notes backup"
            )
            notes_backup_file.write_text(
                "These backup notes are left over from the previous session.",
                encoding="UTF-8",
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
            assert result.clean_exit(), "expected clean exit"
            assert all(map(is_warning_line, result.stderr.splitlines(True)))
            assert modern_editor_interface or machinery.warning_emitted(
                "A backup copy of the old notes was saved",
                caplog.record_tuples,
            ), "expected known warning message in stderr"
            assert (
                modern_editor_interface
                or notes_backup_file.read_text(encoding="UTF-8")
                == "Contents go here"
            )
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config = json.load(infile)
            assert config == {
                "global": {"phrase": "abc"},
                "services": {
                    "sv": {
                        "notes": notes.strip()
                        if modern_editor_interface
                        else edit_result.strip()
                    }
                },
            }

    @Parametrize.NOOP_EDIT_FUNCS
    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters="\n"
            ),
            min_size=1,
            max_size=512,
        ).filter(str.strip),
    )
    def test_noop_edit(
        self,
        edit_func_name: Literal["empty", "space"],
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Abandoning edited notes works."""

        def empty(text: str, *_args: Any, **_kwargs: Any) -> str:
            del text
            return ""

        def space(text: str, *_args: Any, **_kwargs: Any) -> str:
            del text
            return "       " + notes.strip() + "\n\n\n\n\n\n"

        edit_funcs = {"empty": empty, "space": space}
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
                    vault_config={
                        "global": {"phrase": "abc"},
                        "services": {"sv": {"notes": notes.strip()}},
                    },
                )
            )
            notes_backup_file = cli_helpers.config_filename(
                subsystem="notes backup"
            )
            notes_backup_file.write_text(
                "These backup notes are left over from the previous session.",
                encoding="UTF-8",
            )
            monkeypatch.setattr(click, "edit", edit_funcs[edit_func_name])
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
            assert result.clean_exit(empty_stderr=True) or result.error_exit(
                error="the user aborted the request"
            ), "expected clean exit"
            assert (
                modern_editor_interface
                or notes_backup_file.read_text(encoding="UTF-8")
                == "These backup notes are left over from the previous session."
            )
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config = json.load(infile)
            assert config == {
                "global": {"phrase": "abc"},
                "services": {"sv": {"notes": notes.strip()}},
            }

    # TODO(the-13th-letter): Keep this behavior or not, with or without
    # warning?
    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters="\n"
            ),
            min_size=1,
            max_size=512,
        ).filter(str.strip),
    )
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
                    vault_config={
                        "global": {"phrase": "abc"},
                        "services": {"sv": {"notes": "Contents go here"}},
                    },
                )
            )
            notes_backup_file = cli_helpers.config_filename(
                subsystem="notes backup"
            )
            notes_backup_file.write_text(
                "These backup notes are left over from the previous session.",
                encoding="UTF-8",
            )
            monkeypatch.setattr(click, "edit", lambda *_a, **_kw: notes)
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
            assert result.clean_exit(), "expected clean exit"
            assert not result.stderr or all(
                map(is_warning_line, result.stderr.splitlines(True))
            )
            assert not caplog.record_tuples or machinery.warning_emitted(
                "A backup copy of the old notes was saved",
                caplog.record_tuples,
            ), "expected known warning message in stderr"
            assert (
                modern_editor_interface
                or notes_backup_file.read_text(encoding="UTF-8")
                == "Contents go here"
            )
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config = json.load(infile)
            assert config == {
                "global": {"phrase": "abc"},
                "services": {"sv": {"notes": notes.strip()}},
            }


class TestNotesEditingInvalid:
    """Tests concerning editing service notes: invalid/error calls."""

    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters="\n"
            ),
            min_size=1,
            max_size=512,
        ).filter(str.strip),
    )
    def test_abort(
        self,
        notes: str,
    ) -> None:
        """Aborting editing notes works.

        Aborting is only supported with the modern editor interface.

        """
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
                    vault_config={
                        "global": {"phrase": "abc"},
                        "services": {"sv": {"notes": notes.strip()}},
                    },
                )
            )
            monkeypatch.setattr(click, "edit", lambda *_a, **_kw: "")
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    "--config",
                    "--notes",
                    "--modern-editor-interface",
                    "--",
                    "sv",
                ],
                catch_exceptions=False,
            )
            assert result.error_exit(error="the user aborted the request"), (
                "expected known error message"
            )
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config = json.load(infile)
            assert config == {
                "global": {"phrase": "abc"},
                "services": {"sv": {"notes": notes.strip()}},
            }

    def test_abort_no_prior_notes(
        self,
    ) -> None:
        """Aborting editing notes works even if no notes are stored yet.

        Aborting is only supported with the modern editor interface.

        """
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
                    vault_config={
                        "global": {"phrase": "abc"},
                        "services": {},
                    },
                )
            )
            monkeypatch.setattr(click, "edit", lambda *_a, **_kw: "")
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    "--config",
                    "--notes",
                    "--modern-editor-interface",
                    "--",
                    "sv",
                ],
                catch_exceptions=False,
            )
            assert result.error_exit(error="the user aborted the request"), (
                "expected known error message"
            )
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config = json.load(infile)
            assert config == {
                "global": {"phrase": "abc"},
                "services": {},
            }

    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters="\n"
            ),
            max_size=512,
        ),
    )
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
            notes_backup_file.write_text(
                "These backup notes are left over from the previous session.",
                encoding="UTF-8",
            )
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
                == "These backup notes are left over from the previous session."
            )
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config = json.load(infile)
            assert config == vault_config


class TestStoringConfigurationSuccesses:
    """Tests concerning storing the configuration: successes."""

    @Parametrize.CONFIG_EDITING_VIA_CONFIG_FLAG
    def test_store_good_config(
        self,
        command_line: list[str],
        input: str,
        result_config: Any,
    ) -> None:
        """Storing valid settings via `--config` works.

        The format also contains embedded newlines and indentation to make
        the config more readable.

        """
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

    def test_config_directory_nonexistant(
        self,
    ) -> None:
        """Running without an existing config directory works.

        This is a regression test; see [issue\u00a0#6][] for context.
        See also
        [TestStoringConfigurationFailures001.test_config_directory_not_a_file][]
        for a related aspect of this.

        [issue #6]: https://github.com/the-13th-letter/derivepassphrase/issues/6

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
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree(cli_helpers.config_filename(subsystem=None))
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--config", "-p"],
                catch_exceptions=False,
                input="abc\n",
            )
            assert result.clean_exit(), "expected clean exit"
            assert result.stderr == "Passphrase:", (
                "program unexpectedly failed?!"
            )
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config_readback = json.load(infile)
            assert config_readback == {
                "global": {"phrase": "abc"},
                "services": {},
            }, "config mismatch"


class TestStoringConfigurationFailures:
    """Tests concerning storing the configuration: failures."""

    @Parametrize.CONFIG_EDITING_VIA_CONFIG_FLAG_FAILURES
    def test_store_bad_config(
        self,
        command_line: list[str],
        input: str,
        err_text: str,
    ) -> None:
        """Storing invalid settings via `--config` fails."""
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
        assert result.error_exit(error=err_text), (
            "expected error exit and known error message"
        )

    def test_fail_because_no_ssh_key_selection(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
    ) -> None:
        """Not selecting an SSH key during `--config --key` fails."""
        del running_ssh_agent
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

            def prompt_for_selection(*_args: Any, **_kwargs: Any) -> NoReturn:
                raise IndexError(cli_helpers.EMPTY_SELECTION)

            monkeypatch.setattr(
                cli_helpers, "prompt_for_selection", prompt_for_selection
            )
            # Also patch the list of suitable SSH keys, lest we be at
            # the mercy of whatever SSH agent may be running.
            monkeypatch.setattr(
                cli_helpers,
                "get_suitable_ssh_keys",
                callables.suitable_ssh_keys,
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--key", "--config"],
                catch_exceptions=False,
            )
        assert result.error_exit(error="the user aborted the request"), (
            "expected error exit and known error message"
        )

    def test_fail_because_no_ssh_agent(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
    ) -> None:
        """Not running an SSH agent during `--config --key` fails."""
        del running_ssh_agent
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
            monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--key", "--config"],
                catch_exceptions=False,
            )
        assert result.error_exit(error="Cannot find any running SSH agent"), (
            "expected error exit and known error message"
        )

    def test_fail_because_bad_ssh_agent_connection(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
    ) -> None:
        """Not running a reachable SSH agent during `--config --key` fails."""
        running_ssh_agent.require_external_address()
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
            cwd = pathlib.Path.cwd().resolve()
            monkeypatch.setenv("SSH_AUTH_SOCK", str(cwd))
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--key", "--config"],
                catch_exceptions=False,
            )
        assert result.error_exit(error="Cannot connect to the SSH agent"), (
            "expected error exit and known error message"
        )

    @Parametrize.TRY_RACE_FREE_IMPLEMENTATION
    def test_fail_because_read_only_file(
        self,
        try_race_free_implementation: bool,
    ) -> None:
        """Using a read-only configuration file with `--config` fails."""
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
            callables.make_file_readonly(
                cli_helpers.config_filename(subsystem="vault"),
                try_race_free_implementation=try_race_free_implementation,
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--config", "--length=15", "--", DUMMY_SERVICE],
                catch_exceptions=False,
            )
        assert result.error_exit(error="Cannot store vault settings:"), (
            "expected error exit and known error message"
        )

    def test_fail_because_of_custom_error(
        self,
    ) -> None:
        """Triggering internal errors during `--config` leads to failure."""
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
            custom_error = "custom error message"

            def raiser(config: Any) -> None:
                del config
                raise RuntimeError(custom_error)

            monkeypatch.setattr(cli_helpers, "save_config", raiser)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--config", "--length=15", "--", DUMMY_SERVICE],
                catch_exceptions=False,
            )
        assert result.error_exit(error=custom_error), (
            "expected error exit and known error message"
        )

    def test_fail_because_unsetting_and_setting_same_settings(
        self,
    ) -> None:
        """Issuing conflicting settings to `--config` fails."""
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    "--config",
                    "--unset=length",
                    "--length=15",
                    "--",
                    DUMMY_SERVICE,
                ],
                catch_exceptions=False,
            )
        assert result.error_exit(
            error="Attempted to unset and set --length at the same time."
        ), "expected error exit and known error message"

    def test_fail_because_ssh_agent_has_no_keys_loaded(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
    ) -> None:
        """Not holding any SSH keys during `--config --key` fails."""
        del running_ssh_agent
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

            def func(
                *_args: Any,
                **_kwargs: Any,
            ) -> list[_types.SSHKeyCommentPair]:
                return []

            monkeypatch.setattr(ssh_agent.SSHAgentClient, "list_keys", func)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--key", "--config"],
                catch_exceptions=False,
            )
        assert result.error_exit(error="no keys suitable"), (
            "expected error exit and known error message"
        )

    def test_store_config_fail_manual_ssh_agent_runtime_error(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
    ) -> None:
        """Triggering an error in the SSH agent during `--config --key` leads to failure."""
        del running_ssh_agent
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

            def raiser(*_args: Any, **_kwargs: Any) -> None:
                raise ssh_agent.TrailingDataError()

            monkeypatch.setattr(ssh_agent.SSHAgentClient, "list_keys", raiser)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--key", "--config"],
                catch_exceptions=False,
            )
        assert result.error_exit(
            error="violates the communication protocol."
        ), "expected error exit and known error message"

    def test_store_config_fail_manual_ssh_agent_refuses(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
    ) -> None:
        """The SSH agent refusing during `--config --key` leads to failure."""
        del running_ssh_agent
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

            def func(*_args: Any, **_kwargs: Any) -> NoReturn:
                raise ssh_agent.SSHAgentFailedError(
                    _types.SSH_AGENT.FAILURE, b""
                )

            monkeypatch.setattr(ssh_agent.SSHAgentClient, "list_keys", func)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--key", "--config"],
                catch_exceptions=False,
            )
        assert result.error_exit(error="refused to"), (
            "expected error exit and known error message"
        )

    def test_config_directory_not_a_file(
        self,
    ) -> None:
        """Erroring without an existing config directory errors normally.

        That is, the missing configuration directory does not cause any
        errors by itself.

        This is a regression test; see [issue\u00a0#6][] for context.
        See also
        [TestStoringConfigurationSuccesses001.test_config_directory_nonexistant][]
        for a related aspect of this.

        [issue #6]: https://github.com/the-13th-letter/derivepassphrase/issues/6

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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--config", "-p"],
                catch_exceptions=False,
                input="abc\n",
            )
            assert result.error_exit(error="Cannot store vault settings:"), (
                "expected error exit and known error message"
            )


class TestPassphraseUnicodeNormalization:
    """Tests concerning the Unicode normalization of passphrases."""

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
                    vault_config={
                        "services": {
                            DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()
                        }
                    },
                    main_config_str=main_config,
                )
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--debug", *command_line],
                catch_exceptions=False,
                input=input,
            )
        assert result.clean_exit(), "expected clean exit"
        assert machinery.warning_emitted(
            warning_message, caplog.record_tuples
        ), "expected known warning message in stderr"

    @Parametrize.UNICODE_NORMALIZATION_ERROR_INPUTS
    def test_error(
        self,
        main_config: str,
        command_line: list[str],
        input: str | None,
        error_message: str,
    ) -> None:
        """Using unknown Unicode normalization forms fails."""
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
                    vault_config={
                        "services": {
                            DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()
                        }
                    },
                    main_config_str=main_config,
                )
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                catch_exceptions=False,
                input=input,
            )
        assert result.error_exit(
            error="The user configuration file is invalid."
        ), "expected error exit and known error message"
        assert result.error_exit(error=error_message), (
            "expected error exit and known error message"
        )

    @Parametrize.UNICODE_NORMALIZATION_COMMAND_LINES
    def test_error_from_stored_config(
        self,
        command_line: list[str],
    ) -> None:
        """Using unknown Unicode normalization forms in the config fails."""
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
                    vault_config={
                        "services": {
                            DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()
                        }
                    },
                    main_config_str=(
                        "[vault]\ndefault-unicode-normalization-form = 'XXX'\n"
                    ),
                )
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            assert result.error_exit(
                error="The user configuration file is invalid."
            ), "expected error exit and known error message"
            assert result.error_exit(
                error=(
                    "Invalid value 'XXX' for config key "
                    "vault.default-unicode-normalization-form"
                ),
            ), "expected error exit and known error message"


class TestUserConfigurationFileOther:
    """Other tests concerning the user configuration file."""

    def test_bad_user_config_file(
        self,
    ) -> None:
        """Loading a user configuration file in an invalid format fails."""
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
                    main_config_str="This file is not valid TOML.\n",
                )
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--phrase", "--", DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            assert result.error_exit(error="Cannot load user config:"), (
                "expected error exit and known error message"
            )

    def test_user_config_is_a_directory(
        self,
    ) -> None:
        """Loading a user configuration non-file fails."""
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
                    main_config_str="",
                )
            )
            user_config = cli_helpers.config_filename(
                subsystem="user configuration"
            )
            user_config.unlink()
            user_config.mkdir(parents=True, exist_ok=True)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--phrase", "--", DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            assert result.error_exit(error="Cannot load user config:"), (
                "expected error exit and known error message"
            )


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
