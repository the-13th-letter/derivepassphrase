# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Test `derivepassphrase.exporter` and the `derivepassphrase export` CLI."""

from __future__ import annotations

import contextlib
import operator
import os
import pathlib
import string
import types
from typing import TYPE_CHECKING, NamedTuple, TypeVar

import hypothesis
import pytest
from hypothesis import strategies

from derivepassphrase import cli, exporter
from tests import data, machinery
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from typing_extensions import Any, Buffer


class Strategies:
    @strategies.composite
    @staticmethod
    def names(draw: strategies.DrawFn) -> str:
        """Return a strategy for identifier names."""
        first_letter = draw(
            strategies.text(string.ascii_letters, min_size=1, max_size=1),
            label="first_letter",
        )
        rest = draw(
            strategies.text(
                string.ascii_letters + string.digits + "_-", max_size=23
            ),
            label="rest",
        )
        return first_letter + rest

    _T = TypeVar("_T")

    @strategies.composite
    @staticmethod
    def pairs_of_lists(
        draw: strategies.DrawFn,
        strat: strategies.SearchStrategy[_T],
        min_size: int = 1,
        max_size: int = 3,
    ) -> tuple[list[_T], list[_T]]:
        """Return a strategy for two short lists, with unique items."""
        size1 = draw(
            strategies.integers(min_value=min_size, max_value=max_size),
            label="size1",
        )
        size2 = draw(
            strategies.integers(min_value=min_size, max_value=max_size),
            label="size2",
        )
        all_values = draw(
            strategies.lists(
                strat,
                min_size=size1 + size2,
                max_size=size1 + size2,
                unique=True,
            ),
            label="all_values",
        )
        return all_values[:size1], all_values[size1:]


class Parametrize(types.SimpleNamespace):
    EXPECTED_VAULT_PATH = pytest.mark.parametrize(
        ["expected", "path"],
        [
            (pathlib.Path("/tmp"), pathlib.Path("/tmp")),
            (pathlib.Path("~"), pathlib.Path()),
            (pathlib.Path("~/.vault"), None),
        ],
    )
    EXPORT_VAULT_CONFIG_DATA_HANDLER_NAMELISTS = pytest.mark.parametrize(
        ["namelist", "err_pat"],
        [
            pytest.param((), "[Nn]o names given", id="empty"),
            pytest.param(
                ("name1", "", "name2"),
                "[Uu]nder an empty name",
                id="empty-string",
            ),
            pytest.param(
                ("dummy", "name1", "name2"),
                "[Aa]lready registered",
                id="existing",
            ),
        ],
    )


class TestCLIUtilities:
    """Test the command-line utility functions in the `exporter` subpackage."""

    class VaultKeyEnvironment(NamedTuple):
        """An environment configuration for vault key determination.

        Attributes:
            expected:
                The correct vault key value.
            vault_key:
                The value for the `VAULT_KEY` environment variable.
            logname:
                The value for the `LOGNAME` environment variable.
            user:
                The value for the `USER` environment variable.
            username:
                The value for the `USERNAME` environment variable.

        """

        expected: str | None
        """"""
        vault_key: str | None
        """"""
        logname: str | None
        """"""
        user: str | None
        """"""
        username: str | None
        """"""

        @strategies.composite
        @staticmethod
        def strategy(
            draw: strategies.DrawFn,
            allow_missing: bool = False,
        ) -> TestCLIUtilities.VaultKeyEnvironment:
            """Return a vault key environment configuration."""
            text_strategy = strategies.text(
                strategies.characters(min_codepoint=32, max_codepoint=127),
                min_size=1,
                max_size=24,
            )
            env_var_strategy = strategies.one_of(
                strategies.none(),
                text_strategy,
            )
            num_fields = sum(
                1
                for f in TestCLIUtilities.VaultKeyEnvironment._fields
                if f != "expected"
            )
            env_vars: list[str | None] = draw(
                strategies.builds(
                    operator.add,
                    strategies.lists(
                        env_var_strategy,
                        min_size=num_fields - 1,
                        max_size=num_fields - 1,
                    ),
                    strategies.lists(
                        text_strategy
                        if not allow_missing
                        else env_var_strategy,
                        min_size=1,
                        max_size=1,
                    ),
                )
            )
            expected: str | None = None
            for value in reversed(env_vars):
                if value is not None:
                    expected = value
            return TestCLIUtilities.VaultKeyEnvironment(expected, *env_vars)

    @contextlib.contextmanager
    def _setup_environment(self) -> Iterator[pytest.MonkeyPatch]:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch, runner=runner
                )
            )
            yield monkeypatch

    @hypothesis.example(
        VaultKeyEnvironment("4username", None, None, None, "4username")
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment("3user", None, None, "3user", None)
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment("3user", None, None, "3user", "4username")
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment("2logname", None, "2logname", None, None)
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment("2logname", None, "2logname", None, "4username")
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment("2logname", None, "2logname", "3user", None)
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment("2logname", None, "2logname", "3user", "4username")
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment("1vault_key", "1vault_key", None, None, None)
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment(
            "1vault_key", "1vault_key", None, None, "4username"
        )
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment("1vault_key", "1vault_key", None, "3user", None)
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment(
            "1vault_key", "1vault_key", None, "3user", "4username"
        )
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment("1vault_key", "1vault_key", "2logname", None, None)
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment(
            "1vault_key", "1vault_key", "2logname", None, "4username"
        )
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment(
            "1vault_key", "1vault_key", "2logname", "3user", None
        )
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.example(
        VaultKeyEnvironment(
            "1vault_key", "1vault_key", "2logname", "3user", "4username"
        )
    ).via("manual, pre-hypothesis parametrization value")
    @hypothesis.given(
        vault_key_env=VaultKeyEnvironment.strategy().filter(
            lambda env: bool(env.expected)
        ),
    )
    def test_get_vault_key(
        self,
        vault_key_env: VaultKeyEnvironment,
    ) -> None:
        """Look up the vault key in `VAULT_KEY`/`LOGNAME`/`USER`/`USERNAME`.

        The correct environment variable value is used, according to
        their relative priorities.

        """
        expected, vault_key, logname, user, username = vault_key_env
        assert expected is not None
        priority_list = [
            ("VAULT_KEY", vault_key),
            ("LOGNAME", logname),
            ("USER", user),
            ("USERNAME", username),
        ]
        with self._setup_environment() as monkeypatch:
            for key, value in priority_list:
                if value is not None:
                    monkeypatch.setenv(key, value)
            assert os.fsdecode(exporter.get_vault_key()) == expected

    def test_get_vault_key_without_envs(self) -> None:
        """Fail to look up the vault key in the empty environment."""
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.delenv("VAULT_KEY", raising=False)
            monkeypatch.delenv("LOGNAME", raising=False)
            monkeypatch.delenv("USER", raising=False)
            monkeypatch.delenv("USERNAME", raising=False)
            with pytest.raises(KeyError, match="VAULT_KEY"):
                exporter.get_vault_key()

    @Parametrize.EXPECTED_VAULT_PATH
    def test_get_vault_path(
        self,
        expected: pathlib.Path,
        path: str | os.PathLike[str] | None,
    ) -> None:
        """Determine the vault path from `VAULT_PATH`.

        Handle relative paths, absolute paths, and missing paths.

        """
        with self._setup_environment() as monkeypatch:
            if path:
                monkeypatch.setenv(
                    "VAULT_PATH", os.fspath(path) if path is not None else None
                )
            assert (
                exporter.get_vault_path().resolve()
                == expected.expanduser().resolve()
            )

    def test_get_vault_path_without_home(self) -> None:
        """Fail to look up the vault path without `HOME`."""

        def raiser(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("Cannot determine home directory.")  # noqa: EM101,TRY003

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(pathlib.Path, "expanduser", raiser)
            monkeypatch.setattr(os.path, "expanduser", raiser)
            with pytest.raises(
                RuntimeError, match=r"[Cc]annot determine home directory"
            ):
                exporter.get_vault_path()


class TestExportVaultConfigDataHandlerRegistry:
    """Test the registry of `vault` config data exporters."""

    @contextlib.contextmanager
    def _setup_environment(
        self,
        *,
        registry: dict[str, Any] | None = None,
        find_handlers: Callable | None = None,
    ) -> Iterator[pytest.MonkeyPatch]:
        with pytest.MonkeyPatch.context() as monkeypatch:
            if registry is not None:  # pragma: no branch
                monkeypatch.setattr(
                    exporter, "_export_vault_config_data_registry", registry
                )
            if find_handlers is not None:  # pragma: no branch
                monkeypatch.setattr(
                    exporter, "find_vault_config_data_handlers", find_handlers
                )
            yield monkeypatch

    @staticmethod
    def dummy_handler(  # pragma: no cover
        path: str | bytes | os.PathLike | None = None,
        key: str | Buffer | None = None,
        *,
        format: str,
    ) -> Any:
        del path, key
        raise ValueError(format)

    @hypothesis.given(name_data=Strategies.pairs_of_lists(Strategies.names()))
    def test_register_export_vault_config_data_handler(
        self, name_data: tuple[list[str], list[str]]
    ) -> None:
        """Register vault config data export handlers."""
        names1, names2 = name_data
        registry = dict.fromkeys(names1, self.dummy_handler)
        with self._setup_environment(registry=registry):
            dec = exporter.register_export_vault_config_data_handler(*names2)
            assert dec(self.dummy_handler) == self.dummy_handler
            assert registry == dict.fromkeys(
                names1 + names2, self.dummy_handler
            )

    @Parametrize.EXPORT_VAULT_CONFIG_DATA_HANDLER_NAMELISTS
    def test_register_export_vault_config_data_handler_errors(
        self,
        namelist: tuple[str, ...],
        err_pat: str,
    ) -> None:
        """Fail to register a vault config data export handler.

        Fail because e.g. the associated name is missing, or already
        present in the handler registry.

        """

        with self._setup_environment(registry={"dummy": self.dummy_handler}):  # noqa: SIM117
            # TODO(the-13th-letter): Rewrite using parenthesized
            # with-statements.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
            with pytest.raises(ValueError, match=err_pat):
                exporter.register_export_vault_config_data_handler(*namelist)(
                    self.dummy_handler
                )

    def test_export_vault_config_data_bad_handler(self) -> None:
        """Fail to export vault config data without known handlers."""
        with self._setup_environment(registry={}, find_handlers=lambda: None):  # noqa: SIM117
            # TODO(the-13th-letter): Rewrite using parenthesized
            # with-statements.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
            with pytest.raises(
                ValueError,
                match=r"Invalid vault native configuration format",
            ):
                exporter.export_vault_config_data(format="v0.3")


class TestGenericVaultCLIErrors:
    """Test errors in the `derivepassphrase export vault` subpackage.

    These errors are always possible, even if the `export` extra is not
    available.

    """

    @contextlib.contextmanager
    def _setup_environment(
        self, *, vault_config: str | bytes = data.VAULT_V03_CONFIG
    ) -> Iterator[tuple[pytest.MonkeyPatch, machinery.CliRunner]]:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=vault_config,
                    vault_key=data.VAULT_MASTER_KEY,
                )
            )
            yield monkeypatch, runner

    def _call_cli(
        self,
        command_line: list[str],
        *,
        vault_config: str | bytes = data.VAULT_V03_CONFIG,
    ) -> machinery.ReadableResult:
        with self._setup_environment(vault_config=vault_config) as contexts:
            _, runner = contexts
            return runner.invoke(
                cli.derivepassphrase_export_vault,
                command_line,
                catch_exceptions=False,
            )

    def test_invalid_format(self) -> None:
        """Reject invalid vault configuration format names."""
        result = self._call_cli(["-f", "INVALID", "VAULT_PATH"])
        for snippet in ("Invalid value for", "-f", "--format", "INVALID"):
            assert result.error_exit(error=snippet), (
                "expected error exit and known error message"
            )

    @pytest_machinery.skip_if_cryptography_support
    @pytest_machinery.Parametrize.VAULT_CONFIG_FORMATS_DATA
    def test_no_cryptography_error_message(
        self,
        caplog: pytest.LogCaptureFixture,
        config: str | bytes,
        format: str,
        config_data: str,
    ) -> None:
        """Abort export call if no cryptography is available."""
        del config_data
        result = self._call_cli(
            ["-f", format, "VAULT_PATH"], vault_config=config
        )
        assert result.error_exit(
            error=data.CANNOT_LOAD_CRYPTOGRAPHY,
            record_tuples=caplog.record_tuples,
        ), "expected error exit and known error message"
