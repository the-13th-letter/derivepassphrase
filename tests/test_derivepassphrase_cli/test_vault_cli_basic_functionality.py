# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Tests for the `derivepassphrase vault` command-line interface: basic functionality."""

from __future__ import annotations

import contextlib
import json
import textwrap
import types
from typing import TYPE_CHECKING

import pytest
from typing_extensions import Any, NamedTuple

from derivepassphrase import _types, cli, ssh_agent, vault
from derivepassphrase._internals import (
    cli_helpers,
)
from derivepassphrase.ssh_agent import socketprovider
from tests import data, machinery
from tests.data import callables
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    from collections.abc import Generator
    from typing import NoReturn

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


@pytest.fixture
def use_stub_agent_with_address() -> Generator[None, None, None]:
    """Enforce use of the stub SSH agent with socket address."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            ssh_agent.SSHAgentClient,
            "SOCKET_PROVIDERS",
            (_types.BuiltinSSHAgentSocketProvider.STUB_AGENT_WITH_ADDRESS,),
        )
        monkeypatch.setenv(
            "SSH_AUTH_SOCK", machinery.StubbedSSHAgentSocketWithAddress.ADDRESS
        )
        yield


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


class Parametrize(types.SimpleNamespace):
    """Common test parametrizations."""

    AUTO_PROMPT = pytest.mark.parametrize(
        "auto_prompt", [False, True], ids=["normal_prompt", "auto_prompt"]
    )
    CHARSET_NAME = pytest.mark.parametrize(
        "charset_name", ["lower", "upper", "number", "space", "dash", "symbol"]
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
    KEY_INDEX = pytest.mark.parametrize(
        "key_index",
        [
            i
            for i, x in enumerate(data.ALL_KEYS.values(), start=1)
            if x.is_suitable()
        ],
        ids=lambda i: f"index{i}",
    )
    EXPLICIT_SSH_AGENT_SOCKET_PROVIDER = pytest.mark.parametrize(
        ["on_command_line", "in_config"],
        [
            pytest.param(False, True, id="configuration_only"),
            pytest.param(True, False, id="command_line_only"),
            pytest.param(
                True, True, id="command_line_overrides_configuration"
            ),
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
        ["options", "needs_service", "input", "check_success"],
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

    @contextlib.contextmanager
    def _setup_environment(
        self,
        /,
        *,
        config: _types.VaultConfig = {  # noqa: B006
            "services": {
                DUMMY_SERVICE: {**DUMMY_CONFIG_SETTINGS},
            },
        },
        main_config_str: str | None = None,
        registry: dict[str, _types.SSHAgentSocketProvider | str | None]
        | None = None,
    ) -> Generator[machinery.CliRunner, None, None]:
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
                    main_config_str=main_config_str,
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
            if registry is not None:
                monkeypatch.setattr(
                    socketprovider.SocketProvider, "registry", registry
                )
                monkeypatch.setattr(
                    ssh_agent.SSHAgentClient,
                    "SOCKET_PROVIDERS",
                    ("incorrect",),
                )
            yield runner

    def _check_result(
        self, result: machinery.ReadableResult, /, *, multiline: bool = False
    ) -> None:
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

    def _test(
        self,
        command_line: list[str],
        /,
        *,
        config: _types.VaultConfig = {  # noqa: B006
            "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}
        },
        main_config_str: str | None = None,
        registry: dict[str, _types.SSHAgentSocketProvider | str | None]
        | None = None,
        multiline: bool = False,
        input: str | bytes | None = None,
    ) -> None:
        with self._setup_environment(
            config=config, main_config_str=main_config_str, registry=registry
        ) as runner:
            result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=input,
                catch_exceptions=False,
            )
        self._check_result(result, multiline=multiline)

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


@pytest.fixture
def provider_registry() -> dict[
    str, _types.SSHAgentSocketProvider | str | None
]:
    """Set up a controlled SSH agent socket provider registry."""

    def err() -> _types.SSHAgentSocket:
        pytest.fail("Attempting to use the wrong SSH agent socket provider!")

    return {
        "correct": machinery.StubbedSSHAgentSocket,
        "incorrect": err,
    }


# TODO(the-13th-letter): Rewrite the parametrization to be somewhat more
# transparent, but keep it this high-level if possible.
class TestKeyExplicitSSHAgentSocketProvider(TestKeyBasic):
    """Tests for SSH key configuration: explicit SSH agent socket providers."""

    ARG = "--ssh-agent-socket-provider=correct"
    ARG_NONEXISTANT = "--ssh-agent-socket-provider=nonexistant"
    MAIN_CONFIG_STR = textwrap.dedent(r"""
    [vault]
    ssh-agent-socket-provider = "correct"
    """)
    WRONG_CONFIG_STR = textwrap.dedent(r"""
    [vault]
    ssh-agent-socket-provider = "incorrect"
    """)
    NONEXISTANT_CONFIG_STR = textwrap.dedent(r"""
    [vault]
    ssh-agent-socket-provider = "nonexistant"
    """)

    @Parametrize.EXPLICIT_SSH_AGENT_SOCKET_PROVIDER
    @Parametrize.CONFIG_WITH_KEY
    def test_explicit_ssh_agent_socket_provider(
        self,
        provider_registry: dict[
            str, _types.SSHAgentSocketProvider | str | None
        ],
        config: _types.VaultConfig,
        on_command_line: bool,
        in_config: bool,
    ) -> None:
        args = [self.ARG] if on_command_line else []
        main_config_str = (
            self.WRONG_CONFIG_STR
            if in_config and on_command_line
            else self.MAIN_CONFIG_STR
            if in_config
            else None
        )
        self._test(
            [*args, "--", DUMMY_SERVICE],
            config=config,
            registry=provider_registry,
            main_config_str=main_config_str,
        )

    @Parametrize.EXPLICIT_SSH_AGENT_SOCKET_PROVIDER
    @Parametrize.CONFIG_WITH_KEY
    def test_explicit_ssh_agent_socket_provider_not_found(
        self,
        provider_registry: dict[
            str, _types.SSHAgentSocketProvider | str | None
        ],
        config: _types.VaultConfig,
        on_command_line: bool,
        in_config: bool,
    ) -> None:
        assert "nonexistant" not in provider_registry, (
            '"nonexistant" name actually found in registry?!'
        )
        args = [self.ARG_NONEXISTANT] if on_command_line else []
        main_config_str = (
            self.MAIN_CONFIG_STR
            if in_config and on_command_line
            else self.NONEXISTANT_CONFIG_STR
            if in_config
            else None
        )
        with self._setup_environment(
            config=config,
            registry=provider_registry,
            main_config_str=main_config_str,
        ) as runner:
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [*args, "--", DUMMY_SERVICE],
                catch_exceptions=False,
            )
        assert result.error_exit(
            error=" is not in derivepassphrase's provider registry."
        )


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
        use_stub_agent_with_address: None,
        config: _types.VaultConfig,
        key_index: int,
    ) -> None:
        """A command-line SSH key will override the configured key."""
        del use_stub_agent_with_address
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
        use_stub_agent_with_address: None,
    ) -> None:
        """A configured passphrase does not override a configured key."""
        del use_stub_agent_with_address
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
        use_stub_agent_with_address: None,
        caplog: pytest.LogCaptureFixture,
        config: _types.VaultConfig,
        command_line: list[str],
    ) -> None:
        """Configuring a passphrase atop an SSH key works, but warns."""
        del use_stub_agent_with_address
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
    ) -> Generator[machinery.CliRunner, None, None]:
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
        needs_service: bool | None,
        input: str | None,
        check_success: bool,
    ) -> None:
        """We require or forbid a service argument, depending on options."""
        config: _types.VaultConfig = {
            "global": {"phrase": "abc"},
            "services": {},
        }
        result = self._call(
            options if needs_service else [*options, "--", DUMMY_SERVICE],
            config=config,
            input=input,
        )
        if needs_service is not None:
            err_msg = (
                " requires a SERVICE"
                if needs_service
                else " does not take a SERVICE argument"
            )
            assert result.error_exit(error=err_msg), (
                "expected error exit and known error message"
            )
            if check_success:
                result = self._call(
                    [*options, "--", DUMMY_SERVICE]
                    if needs_service
                    else options,
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
