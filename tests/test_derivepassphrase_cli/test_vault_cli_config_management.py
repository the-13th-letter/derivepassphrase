# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Tests for the `derivepassphrase vault` command-line interface: config management.

This includes tests for importing, exporting and setting the
configuration, whether validly or invalidly.  It does not contain any
configuration that is cross-subsystem or that doesn't pertain to
a `vault`-specific CLI call; those are [basic and common subsystem
tests][tests.test_derivepassphrase_cli.test_000_basic].

"""

from __future__ import annotations

import contextlib
import copy
import errno
import json
import os
import pathlib
import shutil
import types
from typing import TYPE_CHECKING

import hypothesis
import pytest
from hypothesis import strategies
from typing_extensions import Any

from derivepassphrase import _types, cli, ssh_agent
from derivepassphrase._internals import (
    cli_helpers,
)
from tests import data, machinery
from tests.data import callables
from tests.machinery import hypothesis as hypothesis_machinery
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import NoReturn

DUMMY_SERVICE = data.DUMMY_SERVICE

DUMMY_KEY1_B64 = data.DUMMY_KEY1_B64


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
    VALID_TEST_CONFIGS = pytest.mark.parametrize(
        "config",
        [conf.config for conf in data.TEST_CONFIGS if conf.is_valid()],
    )
    EXPORT_FORMAT_OPTIONS = pytest.mark.parametrize(
        "export_options",
        [
            [],
            ["--export-as=sh"],
        ],
        ids=["json-format", "sh-format"],
    )
    TRY_RACE_FREE_IMPLEMENTATION = pytest.mark.parametrize(
        "try_race_free_implementation",
        [False, True],
        ids=["racy", "maybe-race-free"],
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
