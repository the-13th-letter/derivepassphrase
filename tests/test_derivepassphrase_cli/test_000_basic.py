# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Tests for the `derivepassphrase` command-line interface: common subsystems.

(Currently, these tests are performed on the `derivepassphrase vault`
subcommand, because that is the main command using all these
subsystems.)

"""

from __future__ import annotations

import contextlib
import ctypes
import json
import socket
import textwrap
import types
from typing import TYPE_CHECKING, ClassVar

import pytest

from derivepassphrase import _types, cli, ssh_agent
from derivepassphrase._internals import cli_helpers, cli_messages
from derivepassphrase.ssh_agent import socketprovider
from tests import data, machinery
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    from collections.abc import Generator

DUMMY_SERVICE = data.DUMMY_SERVICE
DUMMY_PASSPHRASE = data.DUMMY_PASSPHRASE
DUMMY_CONFIG_SETTINGS = data.DUMMY_CONFIG_SETTINGS


class Parametrize(types.SimpleNamespace):
    """Common test parametrizations."""

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
    MISSING_AGENT_SUPPORT = pytest.mark.parametrize(
        ["provider", "exception", "message"],
        [
            pytest.param(
                _types.BuiltinSSHAgentSocketProvider.SSH_AUTH_SOCK_ON_POSIX,
                socketprovider.UnixDomainSocketsNotAvailableError,
                str(
                    cli_messages.TranslatedString(
                        cli_messages.WarnMsgTemplate.NO_UNIX_DOMAIN_SOCKETS
                    )
                ),
                id="unix_domain_sockets",
            ),
            pytest.param(
                _types.BuiltinSSHAgentSocketProvider.WINDOWS_NAMED_PIPE,
                socketprovider.WindowsNamedPipesNotAvailableError,
                str(
                    cli_messages.TranslatedString(
                        cli_messages.WarnMsgTemplate.NO_WINDOWS_NAMED_PIPES
                    )
                ),
                id="windows_named_pipes",
            ),
        ],
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
    ) -> Generator[pytest.MonkeyPatch, None, None]:
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
            # If the setup blows up, then bubble the exception.
            yield monkeypatch  # noqa: RUF075
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

    def _unsupport_provider_and_force_use(
        self,
        provider: _types.BuiltinSSHAgentSocketProvider,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Remove support for the named socket provider."""
        if (
            provider
            == _types.BuiltinSSHAgentSocketProvider.SSH_AUTH_SOCK_ON_POSIX
        ):
            monkeypatch.delattr(socket, "AF_UNIX", raising=False)
        elif (
            provider == _types.BuiltinSSHAgentSocketProvider.WINDOWS_NAMED_PIPE
        ):
            monkeypatch.delattr(ctypes, "WinDLL", raising=False)
        else:
            pytest.fail(f"Don't know how to remove support for {provider!r}.")
        monkeypatch.setattr(
            ssh_agent.SSHAgentClient, "SOCKET_PROVIDERS", [provider]
        )

    @Parametrize.MISSING_AGENT_SUPPORT
    def test_missing_agent_support(
        self,
        caplog: pytest.LogCaptureFixture,
        provider: _types.BuiltinSSHAgentSocketProvider,
        exception: type[NotImplementedError],
        message: str,
    ) -> None:
        """Querying the SSH agent without support fails."""
        del exception
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
            monkeypatch.setenv(
                "SSH_AUTH_SOCK", "the value doesn't even matter"
            )
            self._unsupport_provider_and_force_use(provider, monkeypatch)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--key", "--config"],
                catch_exceptions=False,
            )
        assert result.error_exit(
            error="does not support communicating with it"
        ), "expected error exit and known error message"
        assert machinery.warning_emitted(message, caplog.record_tuples), (
            "expected known warning message in stderr"
        )
