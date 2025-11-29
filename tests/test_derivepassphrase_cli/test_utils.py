# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import base64
import contextlib
import ctypes
import enum
import errno
import io
import json
import logging
import operator
import os
import pathlib
import shlex
import shutil
import socket
import tempfile
import types
import warnings
from typing import TYPE_CHECKING

import click.testing
import hypothesis
import pytest
from hypothesis import strategies
from typing_extensions import Any

from derivepassphrase import _types, cli, ssh_agent, vault
from derivepassphrase._internals import (
    cli_helpers,
    cli_machinery,
)
from derivepassphrase.ssh_agent import socketprovider
from tests import data, machinery
from tests.data import callables
from tests.machinery import hypothesis as hypothesis_machinery
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator
    from typing import NoReturn


DUMMY_SERVICE = data.DUMMY_SERVICE
DUMMY_PASSPHRASE = data.DUMMY_PASSPHRASE
DUMMY_CONFIG_SETTINGS = data.DUMMY_CONFIG_SETTINGS
DUMMY_CONFIG_SETTINGS_AS_CONSTRUCTOR_ARGS = (
    data.DUMMY_CONFIG_SETTINGS_AS_CONSTRUCTOR_ARGS
)
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


def vault_config_exporter_shell_interpreter(  # noqa: C901
    script: str | Iterable[str],
    /,
    *,
    prog_name_list: list[str] | None = None,
    # The click.BaseCommand abstract base class, previously the base
    # class of click.Command and click.Group, was removed in click
    # 8.2.0 without a transition period, and click.Command instated
    # as the common base class instead.  To keep some degree of
    # compatibility with both old click and new click, we explicitly
    # list the (somewhat) concrete base classes we actually care
    # about here.
    command: click.Command | click.Group | None = None,
    runner: machinery.CliRunner | None = None,
) -> Iterator[machinery.ReadableResult]:
    """A rudimentary sh(1) interpreter for `--export-as=sh` output.

    Assumes a script as emitted by `derivepassphrase vault
    --export-as=sh --export -` and interprets the calls to
    `derivepassphrase vault` within.  (One call per line, skips all
    other lines.)  Also has rudimentary support for (quoted)
    here-documents using `HERE` as the marker.

    """
    if isinstance(script, str):  # pragma: no cover
        script = script.splitlines(False)
    if prog_name_list is None:  # pragma: no cover
        prog_name_list = ["derivepassphrase", "vault"]
    if command is None:  # pragma: no cover
        command = cli.derivepassphrase_vault
    if runner is None:  # pragma: no cover
        runner = machinery.CliRunner(mix_stderr=False)
    n = len(prog_name_list)
    it = iter(script)
    while True:
        try:
            raw_line = next(it)
        except StopIteration:
            break
        else:
            line = shlex.split(raw_line)
        input_buffer: list[str] = []
        if line[:n] != prog_name_list:
            continue
        line[:n] = []
        if line and line[-1] == "<<HERE":
            # naive HERE document support
            while True:
                try:
                    raw_line = next(it)
                except StopIteration as exc:  # pragma: no cover
                    msg = "incomplete here document"
                    raise EOFError(msg) from exc
                else:
                    if raw_line == "HERE":
                        break
                    input_buffer.append(raw_line)
            line.pop()
        yield runner.invoke(
            command,
            line,
            catch_exceptions=False,
            input=("".join(x + "\n" for x in input_buffer) or None),
        )


class ListKeysAction(str, enum.Enum):
    """Test fixture settings for [`ssh_agent.SSHAgentClient.list_keys`][].

    Attributes:
        EMPTY: Return an empty key list.
        FAIL: Raise an [`ssh_agent.SSHAgentFailedError`][].
        FAIL_RUNTIME: Raise an [`ssh_agent.TrailingDataError`][].

    """

    EMPTY = enum.auto()
    """"""
    FAIL = enum.auto()
    """"""
    FAIL_RUNTIME = enum.auto()
    """"""

    def __call__(self, *_args: Any, **_kwargs: Any) -> Any:
        """Execute the respective action."""
        # TODO(the-13th-letter): Rewrite using structural pattern
        # matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        if self == self.EMPTY:
            return []
        if self == self.FAIL:
            raise ssh_agent.SSHAgentFailedError(
                _types.SSH_AGENT.FAILURE.value, b""
            )
        if self == self.FAIL_RUNTIME:
            raise ssh_agent.TrailingDataError()
        raise AssertionError()


class SignAction(str, enum.Enum):
    """Test fixture settings for [`ssh_agent.SSHAgentClient.sign`][].

    Attributes:
        FAIL: Raise an [`ssh_agent.SSHAgentFailedError`][].
        FAIL_RUNTIME: Raise an [`ssh_agent.TrailingDataError`][].

    """

    FAIL = enum.auto()
    """"""
    FAIL_RUNTIME = enum.auto()
    """"""

    def __call__(self, *_args: Any, **_kwargs: Any) -> Any:
        """Execute the respective action."""
        # TODO(the-13th-letter): Rewrite using structural pattern
        # matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        if self == self.FAIL:
            raise ssh_agent.SSHAgentFailedError(
                _types.SSH_AGENT.FAILURE.value, b""
            )
        if self == self.FAIL_RUNTIME:
            raise ssh_agent.TrailingDataError()
        raise AssertionError()


class SocketAddressAction(str, enum.Enum):
    """Test fixture settings for the SSH agent socket address.

    Attributes:
        MANGLE_ANNOYING_OS_NAMED_PIPE:
            Mangle the address for the Annoying OS named pipe endpoint.
        MANGLE_SSH_AUTH_SOCK:
            Mangle the address for the UNIX domain socket (the
            `SSH_AUTH_SOCK` environment variable).
        UNSET_ANNOYING_OS_NAMED_PIPE:
            Unset the address for the Annoying OS named pipe endpoint.
        UNSET_SSH_AUTH_SOCK:
            Unset the `SSH_AUTH_SOCK` environment variable (the address
            for the UNIX domain socket).

    """

    MANGLE_ANNOYING_OS_NAMED_PIPE = enum.auto()
    """"""
    MANGLE_SSH_AUTH_SOCK = enum.auto()
    """"""
    UNSET_ANNOYING_OS_NAMED_PIPE = enum.auto()
    """"""
    UNSET_SSH_AUTH_SOCK = enum.auto()
    """"""

    def __call__(
        self, monkeypatch: pytest.MonkeyPatch, /, *_args: Any, **_kwargs: Any
    ) -> None:
        """Execute the respective action."""
        # TODO(the-13th-letter): Rewrite using structural pattern
        # matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        if self in {
            self.MANGLE_ANNOYING_OS_NAMED_PIPE,
            self.UNSET_ANNOYING_OS_NAMED_PIPE,
        }:  # pragma: no cover [unused]
            pass
        elif self == self.MANGLE_SSH_AUTH_SOCK:
            monkeypatch.setenv(
                "SSH_AUTH_SOCK", os.environ["SSH_AUTH_SOCK"] + "~"
            )
        elif self == self.UNSET_SSH_AUTH_SOCK:
            monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
        else:
            raise AssertionError()


class SystemSupportAction(str, enum.Enum):
    """Test fixture settings for [`ssh_agent.SSHAgentClient`][] system support.

    Attributes:
        UNSET_AF_UNIX:
            Ensure lack of support for UNIX domain sockets.
        UNSET_AF_UNIX_AND_ENSURE_USE:
            Ensure lack of support for UNIX domain sockets, and that the
            agent will use this socket provider.
        UNSET_NATIVE:
            Ensure both `UNSET_AF_UNIX` and `UNSET_WINDLL`.
        UNSET_NATIVE_AND_ENSURE_USE:
            Ensure both `UNSET_AF_UNIX` and `UNSET_WINDLL`, and that the
            agent will use the native socket provider.
        UNSET_PROVIDER_LIST:
            Ensure an empty list of SSH agent socket providers.
        UNSET_WINDLL:
            Ensure lack of support for The Annoying OS named pipes.
        UNSET_WINDLL_AND_ENSURE_USE:
            Ensure lack of support for The Annoying OS named pipes, and
            that the agent will use this socket provider.

    """

    UNSET_AF_UNIX = enum.auto()
    """"""
    UNSET_AF_UNIX_AND_ENSURE_USE = enum.auto()
    """"""
    UNSET_NATIVE = enum.auto()
    """"""
    UNSET_NATIVE_AND_ENSURE_USE = enum.auto()
    """"""
    UNSET_PROVIDER_LIST = enum.auto()
    """"""
    UNSET_WINDLL = enum.auto()
    """"""
    UNSET_WINDLL_AND_ENSURE_USE = enum.auto()
    """"""

    def __call__(
        self, monkeypatch: pytest.MonkeyPatch, /, *_args: Any, **_kwargs: Any
    ) -> None:
        """Execute the respective action.

        Args:
            monkeypatch: The current monkeypatch context.

        """
        # TODO(the-13th-letter): Rewrite using structural pattern
        # matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        if self == self.UNSET_PROVIDER_LIST:
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, "SOCKET_PROVIDERS", []
            )
        elif self in {self.UNSET_NATIVE, self.UNSET_NATIVE_AND_ENSURE_USE}:
            self.check_or_ensure_use(
                "native",
                monkeypatch=monkeypatch,
                ensure_use=(self == self.UNSET_NATIVE_AND_ENSURE_USE),
            )
            monkeypatch.delattr(socket, "AF_UNIX", raising=False)
            monkeypatch.delattr(ctypes, "WinDLL", raising=False)
            monkeypatch.delattr(ctypes, "windll", raising=False)
        elif self in {self.UNSET_AF_UNIX, self.UNSET_AF_UNIX_AND_ENSURE_USE}:
            self.check_or_ensure_use(
                "posix",
                monkeypatch=monkeypatch,
                ensure_use=(self == self.UNSET_AF_UNIX_AND_ENSURE_USE),
            )
            monkeypatch.delattr(socket, "AF_UNIX", raising=False)
        elif self in {self.UNSET_WINDLL, self.UNSET_WINDLL_AND_ENSURE_USE}:
            self.check_or_ensure_use(
                "the_annoying_os",
                monkeypatch=monkeypatch,
                ensure_use=(self == self.UNSET_WINDLL_AND_ENSURE_USE),
            )
            monkeypatch.delattr(ctypes, "WinDLL", raising=False)
            monkeypatch.delattr(ctypes, "windll", raising=False)
        else:
            raise AssertionError()

    @staticmethod
    def check_or_ensure_use(
        provider: str, /, *, monkeypatch: pytest.MonkeyPatch, ensure_use: bool
    ) -> None:
        """Check that the named SSH agent socket provider will be used.

        Either ensure that the socket provider will definitely be used,
        or, upon detecting that it won't be used, skip the test.

        Args:
            provider:
                The provider to check for.
            ensure_use:
                If true, ensure that the socket provider will definitely
                be used.  If false, then check for whether it will be
                used, and skip this test if not.
            monkeypatch:
                The monkeypatch context within which the fixture
                adjustments should be executed.

        """
        if ensure_use:
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, "SOCKET_PROVIDERS", [provider]
            )
        else:  # pragma: no cover [external]
            # This branch operates completely on instrumented or on
            # externally defined, non-deterministic state.
            intended: (
                _types.SSHAgentSocketProvider
                | socketprovider.NoSuchProviderError
                | None
            )
            try:
                intended = socketprovider.SocketProvider.lookup(provider)
            except socketprovider.NoSuchProviderError as exc:
                intended = exc
            actual: (
                _types.SSHAgentSocketProvider
                | socketprovider.NoSuchProviderError
                | None
            )
            for name in ssh_agent.SSHAgentClient.SOCKET_PROVIDERS:
                try:
                    actual = socketprovider.SocketProvider.lookup(name)
                except socketprovider.NoSuchProviderError as exc:
                    actual = exc
                if actual is None:
                    continue
                break
            else:
                actual = None
            if intended != actual:
                pytest.skip(
                    f"{provider!r} SSH agent socket provider "
                    f"is not currently in use"
                )


class Parametrize(types.SimpleNamespace):
    """Common test parametrizations."""

    DELETE_CONFIG_INPUT = pytest.mark.parametrize(
        ["command_line", "config", "result_config"],
        [
            pytest.param(
                ["--delete-globals"],
                {"global": {"phrase": "abc"}, "services": {}},
                {"services": {}},
                id="globals",
            ),
            pytest.param(
                ["--delete", "--", DUMMY_SERVICE],
                {
                    "global": {"phrase": "abc"},
                    "services": {DUMMY_SERVICE: {"notes": "..."}},
                },
                {"global": {"phrase": "abc"}, "services": {}},
                id="service",
            ),
            pytest.param(
                ["--clear"],
                {
                    "global": {"phrase": "abc"},
                    "services": {DUMMY_SERVICE: {"notes": "..."}},
                },
                {"services": {}},
                id="all",
            ),
        ],
    )
    BASE_CONFIG_VARIATIONS = pytest.mark.parametrize(
        "config",
        [
            {"global": {"phrase": "my passphrase"}, "services": {}},
            {"global": {"key": DUMMY_KEY1_B64}, "services": {}},
            {
                "global": {"phrase": "abc"},
                "services": {"sv": {"phrase": "my passphrase"}},
            },
            {
                "global": {"phrase": "abc"},
                "services": {"sv": {"key": DUMMY_KEY1_B64}},
            },
            {
                "global": {"phrase": "abc"},
                "services": {"sv": {"key": DUMMY_KEY1_B64, "length": 15}},
            },
        ],
    )
    CONNECTION_HINTS = pytest.mark.parametrize(
        "conn_hint", ["none", "socket", "client"]
    )
    KEY_TO_PHRASE_SETTINGS = pytest.mark.parametrize(
        [
            "list_keys_action",
            "address_action",
            "system_support_action",
            "sign_action",
            "pattern",
        ],
        [
            pytest.param(
                ListKeysAction.EMPTY,
                None,
                None,
                SignAction.FAIL,
                "not loaded into the agent",
                id="key-not-loaded",
            ),
            pytest.param(
                ListKeysAction.FAIL,
                None,
                None,
                SignAction.FAIL,
                "SSH agent failed to or refused to",
                id="list-keys-refused",
            ),
            pytest.param(
                ListKeysAction.FAIL_RUNTIME,
                None,
                None,
                SignAction.FAIL,
                "SSH agent failed to or refused to",
                id="list-keys-protocol-error",
            ),
            pytest.param(
                None,
                SocketAddressAction.UNSET_SSH_AUTH_SOCK,
                None,
                SignAction.FAIL,
                "Cannot find any running SSH agent",
                id="agent-address-missing",
            ),
            pytest.param(
                None,
                SocketAddressAction.MANGLE_SSH_AUTH_SOCK,
                None,
                SignAction.FAIL,
                "Cannot connect to the SSH agent",
                id="agent-address-mangled",
            ),
            pytest.param(
                None,
                None,
                SystemSupportAction.UNSET_NATIVE,
                SignAction.FAIL,
                "does not support communicating with it",
                id="no-agent-support",
            ),
            pytest.param(
                None,
                None,
                SystemSupportAction.UNSET_PROVIDER_LIST,
                SignAction.FAIL,
                "does not support communicating with it",
                id="no-agent-support",
            ),
            pytest.param(
                None,
                None,
                SystemSupportAction.UNSET_AF_UNIX_AND_ENSURE_USE,
                SignAction.FAIL,
                "does not support communicating with it",
                id="no-agent-support",
            ),
            pytest.param(
                None,
                None,
                SystemSupportAction.UNSET_WINDLL_AND_ENSURE_USE,
                SignAction.FAIL,
                "does not support communicating with it",
                id="no-agent-support",
            ),
            pytest.param(
                None,
                None,
                None,
                SignAction.FAIL_RUNTIME,
                "violates the communication protocol",
                id="sign-violates-protocol",
            ),
        ],
    )
    VALIDATION_FUNCTION_INPUT = pytest.mark.parametrize(
        ["vfunc", "input"],
        [
            (cli_machinery.validate_occurrence_constraint, 20),
            (cli_machinery.validate_length, 20),
        ],
    )


class TestConfigLoadingSaving:
    """Tests for the config loading and saving utility functions."""

    @Parametrize.BASE_CONFIG_VARIATIONS
    def test_load(
        self,
        config: Any,
    ) -> None:
        """[`cli_helpers.load_config`][] works for valid configurations."""
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
            config_filename = cli_helpers.config_filename(subsystem="vault")
            with config_filename.open(encoding="UTF-8") as fileobj:
                assert json.load(fileobj) == config
            assert cli_helpers.load_config() == config

    def test_save_bad_config(
        self,
    ) -> None:
        """[`cli_helpers.save_config`][] fails for bad configurations."""
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
            stack.enter_context(
                pytest.raises(ValueError, match="Invalid vault config")
            )
            cli_helpers.save_config(None)  # type: ignore[arg-type]


class TestPrompting:
    """Tests for the prompting utility functions."""

    def test_selection_multiple(self) -> None:
        """[`cli_helpers.prompt_for_selection`][] works in the "multiple" case."""

        @click.command()
        @click.option("--heading", default="Our menu:")
        @click.argument("items", nargs=-1)
        def driver(heading: str, items: list[str]) -> None:
            # from https://montypython.fandom.com/wiki/Spam#The_menu
            items = items or [
                "Egg and bacon",
                "Egg, sausage and bacon",
                "Egg and spam",
                "Egg, bacon and spam",
                "Egg, bacon, sausage and spam",
                "Spam, bacon, sausage and spam",
                "Spam, egg, spam, spam, bacon and spam",
                "Spam, spam, spam, egg and spam",
                (
                    "Spam, spam, spam, spam, spam, spam, baked beans, "
                    "spam, spam, spam and spam"
                ),
                (
                    "Lobster thermidor aux crevettes with a mornay sauce "
                    "garnished with truffle paté, brandy "
                    "and a fried egg on top and spam"
                ),
            ]
            index = cli_helpers.prompt_for_selection(items, heading=heading)
            click.echo("A fine choice: ", nl=False)
            click.echo(items[index])
            click.echo("(Note: Vikings strictly optional.)")

        runner = machinery.CliRunner(mix_stderr=True)
        result = runner.invoke(driver, [], input="9")
        assert result.clean_exit(
            output="""\
Our menu:
[1] Egg and bacon
[2] Egg, sausage and bacon
[3] Egg and spam
[4] Egg, bacon and spam
[5] Egg, bacon, sausage and spam
[6] Spam, bacon, sausage and spam
[7] Spam, egg, spam, spam, bacon and spam
[8] Spam, spam, spam, egg and spam
[9] Spam, spam, spam, spam, spam, spam, baked beans, spam, spam, spam and spam
[10] Lobster thermidor aux crevettes with a mornay sauce garnished with truffle paté, brandy and a fried egg on top and spam
Your selection? (1-10, leave empty to abort): 9
A fine choice: Spam, spam, spam, spam, spam, spam, baked beans, spam, spam, spam and spam
(Note: Vikings strictly optional.)
"""
        ), "expected clean exit"
        result = runner.invoke(
            driver, ["--heading="], input="\n", catch_exceptions=True
        )
        assert result.error_exit(error=IndexError), (
            "expected error exit and known error type"
        )
        assert (
            result.stdout
            == """\
[1] Egg and bacon
[2] Egg, sausage and bacon
[3] Egg and spam
[4] Egg, bacon and spam
[5] Egg, bacon, sausage and spam
[6] Spam, bacon, sausage and spam
[7] Spam, egg, spam, spam, bacon and spam
[8] Spam, spam, spam, egg and spam
[9] Spam, spam, spam, spam, spam, spam, baked beans, spam, spam, spam and spam
[10] Lobster thermidor aux crevettes with a mornay sauce garnished with truffle paté, brandy and a fried egg on top and spam
Your selection? (1-10, leave empty to abort):\x20
"""
        ), "expected known output"
        # click.testing.CliRunner on click < 8.2.1 incorrectly mocks the
        # click prompting machinery, meaning that the mixed output will
        # incorrectly contain a line break, contrary to what the
        # documentation for click.prompt prescribes.
        result = runner.invoke(
            driver, ["--heading="], input="", catch_exceptions=True
        )
        assert result.error_exit(error=IndexError), (
            "expected error exit and known error type"
        )
        assert result.stdout in {
            """\
[1] Egg and bacon
[2] Egg, sausage and bacon
[3] Egg and spam
[4] Egg, bacon and spam
[5] Egg, bacon, sausage and spam
[6] Spam, bacon, sausage and spam
[7] Spam, egg, spam, spam, bacon and spam
[8] Spam, spam, spam, egg and spam
[9] Spam, spam, spam, spam, spam, spam, baked beans, spam, spam, spam and spam
[10] Lobster thermidor aux crevettes with a mornay sauce garnished with truffle paté, brandy and a fried egg on top and spam
Your selection? (1-10, leave empty to abort):\x20
""",
            """\
[1] Egg and bacon
[2] Egg, sausage and bacon
[3] Egg and spam
[4] Egg, bacon and spam
[5] Egg, bacon, sausage and spam
[6] Spam, bacon, sausage and spam
[7] Spam, egg, spam, spam, bacon and spam
[8] Spam, spam, spam, egg and spam
[9] Spam, spam, spam, spam, spam, spam, baked beans, spam, spam, spam and spam
[10] Lobster thermidor aux crevettes with a mornay sauce garnished with truffle paté, brandy and a fried egg on top and spam
Your selection? (1-10, leave empty to abort): """,
        }, "expected known output"

    def test_selection_single(self) -> None:
        """[`cli_helpers.prompt_for_selection`][] works in the "single" case."""

        @click.command()
        @click.option("--item", default="baked beans")
        @click.argument("prompt")
        def driver(item: str, prompt: str) -> None:
            try:
                cli_helpers.prompt_for_selection(
                    [item], heading="", single_choice_prompt=prompt
                )
            except IndexError:
                click.echo("Boo.")
                raise
            else:
                click.echo("Great!")

        runner = machinery.CliRunner(mix_stderr=True)
        result = runner.invoke(
            driver, ["Will replace with spam. Confirm, y/n?"], input="y"
        )
        assert result.clean_exit(
            output="""\
[1] baked beans
Will replace with spam. Confirm, y/n? y
Great!
"""
        ), "expected clean exit"
        result = runner.invoke(
            driver,
            ['Will replace with spam, okay? (Please say "y" or "n".)'],
            input="\n",
        )
        assert result.error_exit(error=IndexError), (
            "expected error exit and known error type"
        )
        assert (
            result.stdout
            == """\
[1] baked beans
Will replace with spam, okay? (Please say "y" or "n".):\x20
Boo.
"""
        ), "expected known output"
        # click.testing.CliRunner on click < 8.2.1 incorrectly mocks the
        # click prompting machinery, meaning that the mixed output will
        # incorrectly contain a line break, contrary to what the
        # documentation for click.prompt prescribes.
        result = runner.invoke(
            driver,
            ['Will replace with spam, okay? (Please say "y" or "n".)'],
            input="",
        )
        assert result.error_exit(error=IndexError), (
            "expected error exit and known error type"
        )
        assert result.stdout in {
            """\
[1] baked beans
Will replace with spam, okay? (Please say "y" or "n".):\x20
Boo.
""",
            """\
[1] baked beans
Will replace with spam, okay? (Please say "y" or "n".): Boo.
""",
        }, "expected known output"

    def test_passphrase(
        self,
    ) -> None:
        """[`cli_helpers.prompt_for_passphrase`][] works."""
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                click,
                "prompt",
                lambda *a, **kw: json.dumps({"args": a, "kwargs": kw}),
            )
            res = json.loads(cli_helpers.prompt_for_passphrase())
        err_msg = "missing arguments to passphrase prompt"
        assert "args" in res, err_msg
        assert "kwargs" in res, err_msg
        assert res["args"][:1] == ["Passphrase"], err_msg
        assert res["kwargs"].get("default") == "", err_msg
        assert not res["kwargs"].get("show_default", True), err_msg
        assert res["kwargs"].get("err"), err_msg
        assert res["kwargs"].get("hide_input"), err_msg


class TestLoggingMachinery:
    """Tests for the logging utility functions."""

    def test_standard_logging_context_manager(
        self,
        caplog: pytest.LogCaptureFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The standard logging context manager works.

        It registers its handlers, once, and emits formatted calls to
        standard error prefixed with the program name.

        """
        prog_name = cli_machinery.StandardCLILogging.prog_name
        package_name = cli_machinery.StandardCLILogging.package_name
        logger = logging.getLogger(package_name)
        deprecation_logger = logging.getLogger(f"{package_name}.deprecation")
        logging_cm = cli_machinery.StandardCLILogging.ensure_standard_logging()
        with logging_cm:
            assert (
                sum(
                    1
                    for h in logger.handlers
                    if h is cli_machinery.StandardCLILogging.cli_handler
                )
                == 1
            )
            logger.warning("message 1")
            with logging_cm:
                deprecation_logger.warning("message 2")
                assert (
                    sum(
                        1
                        for h in logger.handlers
                        if h is cli_machinery.StandardCLILogging.cli_handler
                    )
                    == 1
                )
                assert capsys.readouterr() == (
                    "",
                    (
                        f"{prog_name}: Warning: message 1\n"
                        f"{prog_name}: Deprecation warning: message 2\n"
                    ),
                )
            logger.warning("message 3")
            assert (
                sum(
                    1
                    for h in logger.handlers
                    if h is cli_machinery.StandardCLILogging.cli_handler
                )
                == 1
            )
            assert capsys.readouterr() == (
                "",
                f"{prog_name}: Warning: message 3\n",
            )
            assert caplog.record_tuples == [
                (package_name, logging.WARNING, "message 1"),
                (f"{package_name}.deprecation", logging.WARNING, "message 2"),
                (package_name, logging.WARNING, "message 3"),
            ]

    def test_warnings_context_manager(
        self,
        caplog: pytest.LogCaptureFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The standard warnings logging context manager works.

        It registers its handlers, once, and emits formatted calls to
        standard error prefixed with the program name.  It also adheres
        to the global warnings filter concerning which messages it
        actually emits to standard error.

        """
        warnings_cm = (
            cli_machinery.StandardCLILogging.ensure_standard_warnings_logging()
        )
        THE_FUTURE = "the future will be here sooner than you think"  # noqa: N806
        JUST_TESTING = "just testing whether warnings work"  # noqa: N806
        with warnings_cm:
            assert (
                sum(
                    1
                    for h in logging.getLogger("py.warnings").handlers
                    if h is cli_machinery.StandardCLILogging.warnings_handler
                )
                == 1
            )
            warnings.warn(UserWarning(JUST_TESTING), stacklevel=1)
            with warnings_cm:
                warnings.warn(FutureWarning(THE_FUTURE), stacklevel=1)
                _out, err = capsys.readouterr()
                err_lines = err.splitlines(True)
                assert any(
                    f"UserWarning: {JUST_TESTING}" in line
                    for line in err_lines
                )
                assert any(
                    f"FutureWarning: {THE_FUTURE}" in line
                    for line in err_lines
                )
            warnings.warn(UserWarning(JUST_TESTING), stacklevel=1)
            _out, err = capsys.readouterr()
            err_lines = err.splitlines(True)
            assert any(
                f"UserWarning: {JUST_TESTING}" in line for line in err_lines
            )
            assert not any(
                f"FutureWarning: {THE_FUTURE}" in line for line in err_lines
            )
            record_tuples = caplog.record_tuples
            assert [tup[:2] for tup in record_tuples] == [
                ("py.warnings", logging.WARNING),
                ("py.warnings", logging.WARNING),
                ("py.warnings", logging.WARNING),
            ]
            assert f"UserWarning: {JUST_TESTING}" in record_tuples[0][2]
            assert f"FutureWarning: {THE_FUTURE}" in record_tuples[1][2]
            assert f"UserWarning: {JUST_TESTING}" in record_tuples[2][2]


class TestExportConfigAsShellScript:
    """Tests the utility functions for exporting configs in `sh` format."""

    def export_as_sh_helper(
        self,
        config: Any,
    ) -> None:
        """Emits a config in sh(1) format, then reads it back to verify it.

        This function exports the configuration, sets up a new
        enviroment, then calls
        [`vault_config_exporter_shell_interpreter`][] on the export
        script, verifying that each command ran successfully and that
        the final configuration matches the initial one.

        Args:
            config:
                The configuration to emit and read back.

        """
        prog_name_list = ("derivepassphrase", "vault")
        with io.StringIO() as outfile:
            cli_helpers.print_config_as_sh_script(
                config, outfile=outfile, prog_name_list=prog_name_list
            )
            script = outfile.getvalue()
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
            for result in vault_config_exporter_shell_interpreter(script):
                assert result.clean_exit()
            assert cli_helpers.load_config() == config

    @hypothesis.given(
        global_config_settable=hypothesis_machinery.vault_full_service_config(),
        global_config_importable=strategies.fixed_dictionaries(
            {},
            optional={
                "key": strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=128,
                ),
                "phrase": strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=64,
                ),
            },
        ),
    )
    def test_export_as_sh_global(
        self,
        global_config_settable: _types.VaultConfigServicesSettings,
        global_config_importable: _types.VaultConfigServicesSettings,
    ) -> None:
        """Exporting configurations as sh(1) script works.

        Here, we check global-only configurations which use both
        settings settable via `--config` and settings requiring
        `--import`.

        The actual verification is done by [`export_as_sh_helper`][].

        """
        config: _types.VaultConfig = {
            "global": global_config_settable | global_config_importable,
            "services": {},
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        return self.export_as_sh_helper(config)

    @hypothesis.given(
        global_config_importable=strategies.fixed_dictionaries(
            {},
            optional={
                "key": strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=128,
                ),
                "phrase": strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=64,
                ),
            },
        ),
    )
    def test_export_as_sh_global_only_imports(
        self,
        global_config_importable: _types.VaultConfigServicesSettings,
    ) -> None:
        """Exporting configurations as sh(1) script works.

        Here, we check global-only configurations which only use
        settings requiring `--import`.

        The actual verification is done by [`export_as_sh_helper`][].

        """
        config: _types.VaultConfig = {
            "global": global_config_importable,
            "services": {},
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        if not config["global"]:
            config.pop("global")
        return self.export_as_sh_helper(config)

    @hypothesis.given(
        service_name=strategies.text(
            alphabet=strategies.characters(
                min_codepoint=32,
                max_codepoint=126,
            ),
            min_size=4,
            max_size=64,
        ),
        service_config_settable=hypothesis_machinery.vault_full_service_config(),
        service_config_importable=strategies.fixed_dictionaries(
            {},
            optional={
                "key": strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=128,
                ),
                "phrase": strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=64,
                ),
                "notes": strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                        include_characters=("\n", "\f", "\t"),
                    ),
                    max_size=256,
                ),
            },
        ),
    )
    def test_export_as_sh_service(
        self,
        service_name: str,
        service_config_settable: _types.VaultConfigServicesSettings,
        service_config_importable: _types.VaultConfigServicesSettings,
    ) -> None:
        """Exporting configurations as sh(1) script works.

        Here, we check service-only configurations which use both
        settings settable via `--config` and settings requiring
        `--import`.

        The actual verification is done by [`export_as_sh_helper`][].

        """
        config: _types.VaultConfig = {
            "services": {
                service_name: (
                    service_config_settable | service_config_importable
                ),
            },
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        return self.export_as_sh_helper(config)

    @hypothesis.given(
        service_name=strategies.text(
            alphabet=strategies.characters(
                min_codepoint=32,
                max_codepoint=126,
            ),
            min_size=4,
            max_size=64,
        ),
        service_config_importable=strategies.fixed_dictionaries(
            {},
            optional={
                "key": strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=128,
                ),
                "phrase": strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=64,
                ),
                "notes": strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                        include_characters=("\n", "\f", "\t"),
                    ),
                    max_size=256,
                ),
            },
        ),
    )
    def test_export_as_sh_service_only_imports(
        self,
        service_name: str,
        service_config_importable: _types.VaultConfigServicesSettings,
    ) -> None:
        """Exporting configurations as sh(1) script works.

        Here, we check service-only configurations which only use
        settings requiring `--import`.

        The actual verification is done by [`export_as_sh_helper`][].

        """
        config: _types.VaultConfig = {
            "services": {
                service_name: service_config_importable,
            },
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        return self.export_as_sh_helper(config)


class TestTempdir:
    """Tests for the temporary directory handling utility functions."""

    # The Annoying OS appears to silently truncate spaces at the end of
    # filenames.
    @hypothesis.given(
        env_var=strategies.sampled_from(["TMPDIR", "TEMP", "TMP"]),
        suffix=strategies.builds(
            operator.add,
            strategies.text(
                tuple(" 0123456789abcdefghijklmnopqrstuvwxyz"),
                min_size=11,
                max_size=11,
            ),
            strategies.text(
                tuple("0123456789abcdefghijklmnopqrstuvwxyz"),
                min_size=1,
                max_size=1,
            ),
        ),
    )
    @hypothesis.example(env_var="", suffix=".")
    def test_get_tempdir(
        self,
        env_var: str,
        suffix: str,
    ) -> None:
        """[`cli_helpers.get_tempdir`][] returns a temporary directory.

        If it is not the same as the temporary directory determined by
        [`tempfile.gettempdir`][], then assert that
        `tempfile.gettempdir` returned the current directory and
        `cli_helpers.get_tempdir` returned the configuration directory.

        """

        @contextlib.contextmanager
        def make_temporary_directory(
            path: pathlib.Path,
        ) -> Iterator[pathlib.Path]:
            try:
                path.mkdir()
                yield path
            finally:
                shutil.rmtree(path)

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
            old_tempdir = os.fsdecode(tempfile.gettempdir())
            monkeypatch.delenv("TMPDIR", raising=False)
            monkeypatch.delenv("TEMP", raising=False)
            monkeypatch.delenv("TMP", raising=False)
            monkeypatch.setattr(tempfile, "tempdir", None)
            temp_path = pathlib.Path.cwd() / suffix
            if env_var:
                monkeypatch.setenv(env_var, os.fsdecode(temp_path))
                stack.enter_context(make_temporary_directory(temp_path))
            new_tempdir = os.fsdecode(tempfile.gettempdir())
            hypothesis.assume(
                temp_path.resolve() == pathlib.Path.cwd().resolve()
                or old_tempdir != new_tempdir
            )
            system_tempdir = os.fsdecode(tempfile.gettempdir())
            our_tempdir = cli_helpers.get_tempdir()
            assert system_tempdir == os.fsdecode(our_tempdir) or (
                # TODO(the-13th-letter): `pytest_machinery.isolated_config`
                # guarantees that `Path.cwd() == config_filename(None)`.
                # So this sub-branch ought to never trigger in our
                # tests.
                system_tempdir == os.getcwd()  # noqa: PTH109
                and our_tempdir == cli_helpers.config_filename(subsystem=None)
            )
        assert not temp_path.exists(), f"temp path {temp_path} not cleaned up!"

    def test_get_tempdir_force_default(self) -> None:
        """[`cli_helpers.get_tempdir`][] returns a temporary directory.

        If all candidates are mocked to fail for the standard temporary
        directory choices, then we return the `derivepassphrase`
        configuration directory.

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
                    vault_config={"services": {}},
                )
            )
            monkeypatch.delenv("TMPDIR", raising=False)
            monkeypatch.delenv("TEMP", raising=False)
            monkeypatch.delenv("TMP", raising=False)
            config_dir = cli_helpers.config_filename(subsystem=None)

            def is_dir_false(
                self: pathlib.Path,
                /,
                *,
                follow_symlinks: bool = False,
            ) -> bool:
                del self, follow_symlinks
                return False

            def is_dir_error(
                self: pathlib.Path,
                /,
                *,
                follow_symlinks: bool = False,
            ) -> bool:
                del follow_symlinks
                raise OSError(
                    errno.EACCES,
                    os.strerror(errno.EACCES),
                    str(self),
                )

            monkeypatch.setattr(pathlib.Path, "is_dir", is_dir_false)
            assert cli_helpers.get_tempdir() == config_dir

            monkeypatch.setattr(pathlib.Path, "is_dir", is_dir_error)
            assert cli_helpers.get_tempdir() == config_dir


# TODO(the-13th-letter): Use a better class name, or consider keeping them
# as top-level functions.
class TestMisc:
    """Miscellaneous tests for the command-line utility functions."""

    @Parametrize.DELETE_CONFIG_INPUT
    def test_repeated_config_deletion(
        self,
        command_line: list[str],
        config: _types.VaultConfig,
        result_config: _types.VaultConfig,
    ) -> None:
        """Repeatedly removing the same parts of a configuration works."""
        for start_config in [config, result_config]:
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
                        vault_config=start_config,
                    )
                )
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    command_line,
                    catch_exceptions=False,
                )
                assert result.clean_exit(empty_stderr=True), (
                    "expected clean exit"
                )
                with cli_helpers.config_filename(subsystem="vault").open(
                    encoding="UTF-8"
                ) as infile:
                    config_readback = json.load(infile)
                assert config_readback == result_config

    def test_phrase_from_key_manually(self) -> None:
        """The dummy service, key and config settings are consistent."""
        assert (
            vault.Vault(
                phrase=DUMMY_PHRASE_FROM_KEY1,
                **DUMMY_CONFIG_SETTINGS_AS_CONSTRUCTOR_ARGS,
            ).generate(DUMMY_SERVICE)
            == DUMMY_RESULT_KEY1
        )

    @Parametrize.VALIDATION_FUNCTION_INPUT
    def test_validate_constraints_manually(
        self,
        vfunc: Callable[[click.Context, click.Parameter, Any], int | None],
        input: int,
    ) -> None:
        """Command-line argument constraint validation works."""
        ctx = cli.derivepassphrase_vault.make_context(cli.PROG_NAME, [])
        param = cli.derivepassphrase_vault.params[0]
        assert vfunc(ctx, param, input) == input

    @Parametrize.CONNECTION_HINTS
    def test_get_suitable_ssh_keys(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
        conn_hint: str,
    ) -> None:
        """[`cli_helpers.get_suitable_ssh_keys`][] works."""
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient,
                "list_keys",
                callables.list_keys,
            )
            hint: ssh_agent.SSHAgentClient | _types.SSHAgentSocket | None
            # TODO(the-13th-letter): Rewrite using structural pattern
            # matching.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
            if conn_hint == "client":
                hint = ssh_agent.SSHAgentClient()
            elif conn_hint == "socket":
                if isinstance(
                    running_ssh_agent.socket, str
                ):  # pragma: no cover
                    if not hasattr(socket, "AF_UNIX"):
                        pytest.skip("socket module does not support AF_UNIX")
                    # socket.AF_UNIX is not defined everywhere.
                    hint = socket.socket(family=socket.AF_UNIX)  # type: ignore[attr-defined]
                    hint.connect(running_ssh_agent.socket)
                else:  # pragma: no cover
                    hint = running_ssh_agent.socket()
            else:
                assert conn_hint == "none"
                hint = None
            exception: Exception | None = None
            try:
                list(cli_helpers.get_suitable_ssh_keys(hint))
            except RuntimeError:  # pragma: no cover
                pass
            except Exception as e:  # noqa: BLE001 # pragma: no cover
                exception = e
            finally:
                assert exception is None, (
                    "exception querying suitable SSH keys"
                )

    @Parametrize.KEY_TO_PHRASE_SETTINGS
    def test_key_to_phrase(
        self,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
        list_keys_action: ListKeysAction | None,
        system_support_action: SystemSupportAction | None,
        address_action: SocketAddressAction | None,
        sign_action: SignAction,
        pattern: str,
    ) -> None:
        """All errors in [`cli_helpers.key_to_phrase`][] are handled."""

        class ErrCallback(BaseException):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args[:1])
                self.args = args
                self.kwargs = kwargs

        def err(*args: Any, **_kwargs: Any) -> NoReturn:
            raise ErrCallback(*args, **_kwargs)

        with pytest.MonkeyPatch.context() as monkeypatch:
            loaded_keys = list(
                ssh_agent_client_with_test_keys_loaded.list_keys()
            )
            loaded_key = base64.standard_b64encode(loaded_keys[0][0])
            monkeypatch.setattr(ssh_agent.SSHAgentClient, "sign", sign_action)
            if list_keys_action:
                monkeypatch.setattr(
                    ssh_agent.SSHAgentClient, "list_keys", list_keys_action
                )
            if address_action:
                address_action(monkeypatch)
            if system_support_action:
                system_support_action(monkeypatch)
            with pytest.raises(ErrCallback, match=pattern) as excinfo:
                cli_helpers.key_to_phrase(loaded_key, error_callback=err)
            if list_keys_action == ListKeysAction.FAIL_RUNTIME:
                assert excinfo.value.kwargs
                assert isinstance(
                    excinfo.value.kwargs["exc_info"],
                    ssh_agent.SSHAgentFailedError,
                )
                assert excinfo.value.kwargs["exc_info"].__context__ is not None
                assert isinstance(
                    excinfo.value.kwargs["exc_info"].__context__,
                    ssh_agent.TrailingDataError,
                )
