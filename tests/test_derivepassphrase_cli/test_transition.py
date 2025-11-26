# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

# TODO(the-13th-letter): Remove this module in v1.0.
# https://the13thletter.info/derivepassphrase/latest/upgrade-notes/#upgrading-to-v1.0

from __future__ import annotations

import contextlib
import errno
import json
import logging
import os
import pathlib

import click.testing
import pytest
from typing_extensions import Any

from derivepassphrase import cli, vault
from derivepassphrase._internals import (
    cli_helpers,
)
from tests import data, machinery
from tests.data import callables
from tests.machinery import pytest as pytest_machinery
from tests.test_derivepassphrase_cli import (
    test_utils,
    test_vault_cli_basic_functionality,
)

DUMMY_SERVICE = data.DUMMY_SERVICE
DUMMY_PASSPHRASE = data.DUMMY_PASSPHRASE
DUMMY_CONFIG_SETTINGS = data.DUMMY_CONFIG_SETTINGS


class Parametrize(
    test_vault_cli_basic_functionality.Parametrize, test_utils.Parametrize
):
    """Common test parametrizations."""

    BAD_CONFIGS = pytest.mark.parametrize(
        "config",
        [
            {"global": "", "services": {}},
            {"global": 0, "services": {}},
            {
                "global": {"phrase": "abc"},
                "services": False,
            },
            {
                "global": {"phrase": "abc"},
                "services": True,
            },
            {
                "global": {"phrase": "abc"},
                "services": None,
            },
        ],
    )


class TestConfigMigrationMachinery:
    """Tests for the configuration file migration machinery."""

    @Parametrize.BASE_CONFIG_VARIATIONS
    def test_load_config_backup(
        self,
        config: Any,
    ) -> None:
        """Loading the old settings file works."""
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
            cli_helpers.config_filename(
                subsystem="old settings.json"
            ).write_text(json.dumps(config, indent=2) + "\n", encoding="UTF-8")
            assert cli_helpers.migrate_and_load_old_config()[0] == config

    @Parametrize.BASE_CONFIG_VARIATIONS
    def test_migration(
        self,
        config: Any,
    ) -> None:
        """Migrating the old settings file works."""
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
            cli_helpers.config_filename(
                subsystem="old settings.json"
            ).write_text(json.dumps(config, indent=2) + "\n", encoding="UTF-8")
            assert cli_helpers.migrate_and_load_old_config() == (config, None)

    @Parametrize.BASE_CONFIG_VARIATIONS
    def test_migration_error(
        self,
        config: Any,
    ) -> None:
        """Migrating the old settings file atop a directory fails."""
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
            cli_helpers.config_filename(
                subsystem="old settings.json"
            ).write_text(json.dumps(config, indent=2) + "\n", encoding="UTF-8")
            cli_helpers.config_filename(subsystem="vault").mkdir(
                parents=True, exist_ok=True
            )
            config2, err = cli_helpers.migrate_and_load_old_config()
            assert config2 == config
            assert isinstance(err, OSError)
            # The Annoying OS uses EEXIST, other OSes use EISDIR.
            assert err.errno in {errno.EISDIR, errno.EEXIST}

    @Parametrize.BAD_CONFIGS
    def test_bad_config_migration(
        self,
        config: Any,
    ) -> None:
        """Migrating an invalid old settings file fails."""
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
            cli_helpers.config_filename(
                subsystem="old settings.json"
            ).write_text(json.dumps(config, indent=2) + "\n", encoding="UTF-8")
            with pytest.raises(
                ValueError, match=cli_helpers.INVALID_VAULT_CONFIG
            ):
                cli_helpers.migrate_and_load_old_config()

    def test_completion_supports_old_config_file(
        self,
    ) -> None:
        """Completing service names from the old settings file works."""
        config = {"services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()}}
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
            old_name = cli_helpers.config_filename(
                subsystem="old settings.json"
            )
            new_name = cli_helpers.config_filename(subsystem="vault")
            old_name.unlink(missing_ok=True)
            new_name.rename(old_name)
            assert cli_helpers.shell_complete_service(
                click.Context(cli.derivepassphrase),
                click.Argument(["some_parameter"]),
                "",
            ) == [DUMMY_SERVICE]


class TestArgumentForwarding:
    """Tests for the argument forwarding up to v1.0."""

    def test_forward_export_vault_path_parameter(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Forwarding arguments from "export" to "export vault" works."""
        pytest.importorskip("cryptography", minversion="38.0")
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
                    vault_config=data.VAULT_V03_CONFIG,
                    vault_key=data.VAULT_MASTER_KEY,
                )
            )
            monkeypatch.setenv("VAULT_KEY", data.VAULT_MASTER_KEY)
            result = runner.invoke(
                cli.derivepassphrase,
                ["export", "VAULT_PATH"],
            )
        assert result.clean_exit(empty_stderr=False), "expected clean exit"
        assert machinery.deprecation_warning_emitted(
            "A subcommand will be required here in v1.0", caplog.record_tuples
        )
        assert machinery.deprecation_warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        assert json.loads(result.stdout) == data.VAULT_V03_CONFIG_DATA

    def test_forward_export_vault_empty_commandline(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Deferring from "export" to "export vault" works."""
        pytest.importorskip("cryptography", minversion="38.0")
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
                ["export"],
            )
        assert machinery.deprecation_warning_emitted(
            "A subcommand will be required here in v1.0", caplog.record_tuples
        )
        assert machinery.deprecation_warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        assert result.error_exit(error="Missing argument 'PATH'"), (
            "expected error exit and known error type"
        )

    @Parametrize.CHARSET_NAME
    def test_forward_vault_disable_character_set(
        self,
        caplog: pytest.LogCaptureFixture,
        charset_name: str,
    ) -> None:
        """Forwarding arguments from top-level to "vault" works."""
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
                cli.derivepassphrase,
                [option, "0", "-p", "--", DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=False), "expected clean exit"
        assert machinery.deprecation_warning_emitted(
            "A subcommand will be required here in v1.0", caplog.record_tuples
        )
        assert machinery.deprecation_warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        for c in charset:
            assert c not in result.stdout, (
                f"derived password contains forbidden character {c!r}"
            )

    def test_forward_vault_empty_command_line(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Deferring from top-level to "vault" works."""
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
                [],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        assert machinery.deprecation_warning_emitted(
            "A subcommand will be required here in v1.0", caplog.record_tuples
        )
        assert machinery.deprecation_warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        assert result.error_exit(
            error="Deriving a passphrase requires a SERVICE."
        ), "expected error exit and known error type"


class TestConfigMigration:
    """Tests for the configuration file migration up to v1.0."""

    def test_export_and_automatic_migration(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Exporting from (and migrating) the old settings file works."""
        caplog.set_level(logging.INFO)
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
            cli_helpers.config_filename(
                subsystem="old settings.json"
            ).write_text(
                json.dumps(
                    {"services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}},
                    indent=2,
                )
                + "\n",
                encoding="UTF-8",
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--export", "-"],
                catch_exceptions=False,
            )
        assert result.clean_exit(), "expected clean exit"
        assert machinery.deprecation_warning_emitted(
            "v0.1-style config file", caplog.record_tuples
        ), "expected known warning message in stderr"
        assert machinery.deprecation_info_emitted(
            "Successfully migrated to ", caplog.record_tuples
        ), "expected known warning message in stderr"

    def test_export_and_automatic_migration_with_errors(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Exporting from (and not migrating) the old settings file fails."""
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
            cli_helpers.config_filename(
                subsystem="old settings.json"
            ).write_text(
                json.dumps(
                    {"services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}},
                    indent=2,
                )
                + "\n",
                encoding="UTF-8",
            )

            def raiser(*_args: Any, **_kwargs: Any) -> None:
                raise OSError(
                    errno.EACCES,
                    os.strerror(errno.EACCES),
                    cli_helpers.config_filename(subsystem="vault"),
                )

            monkeypatch.setattr(os, "replace", raiser)
            monkeypatch.setattr(pathlib.Path, "rename", raiser)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ["--export", "-"],
                catch_exceptions=False,
            )
        assert result.clean_exit(), "expected clean exit"
        assert machinery.deprecation_warning_emitted(
            "v0.1-style config file", caplog.record_tuples
        ), "expected known warning message in stderr"
        assert machinery.warning_emitted(
            "Failed to migrate to ", caplog.record_tuples
        ), "expected known warning message in stderr"
