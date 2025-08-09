# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import contextlib
import copy
import errno
import json
import pathlib
import queue
import shutil
from typing import TYPE_CHECKING, cast

import hypothesis
import pytest
from hypothesis import stateful, strategies
from typing_extensions import Any, NamedTuple, TypeAlias

from derivepassphrase import _types, cli
from derivepassphrase._internals import cli_helpers
from tests import data, machinery
from tests.machinery import hypothesis as hypothesis_machinery
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    import multiprocessing
    from collections.abc import Iterable

    from typing_extensions import Literal

# All tests in this module are heavy-duty tests.
pytestmark = [pytest_machinery.heavy_duty]

KNOWN_SERVICES = (data.DUMMY_SERVICE, "email", "bank", "work")
"""Known service names.  Used for the [`ConfigManagementStateMachine`][]."""
VALID_PROPERTIES = (
    "length",
    "repeat",
    "upper",
    "lower",
    "number",
    "space",
    "dash",
    "symbol",
)
"""Known vault properties.  Used for the [`ConfigManagementStateMachine`][]."""


def build_reduced_vault_config_settings(
    config: _types.VaultConfigServicesSettings,
    keys_to_prune: frozenset[str],
) -> _types.VaultConfigServicesSettings:
    """Return a service settings object with certain keys pruned.

    Args:
        config:
            The original service settings object.
        keys_to_prune:
            The keys to prune from the settings object.

    """
    config2 = copy.deepcopy(config)
    for key in keys_to_prune:
        config2.pop(key, None)  # type: ignore[misc]
    return config2


SERVICES_STRATEGY = strategies.builds(
    build_reduced_vault_config_settings,
    hypothesis_machinery.vault_full_service_config(),
    strategies.sets(
        strategies.sampled_from(VALID_PROPERTIES),
        max_size=7,
    ),
)
"""A hypothesis strategy to build incomplete service configurations."""


def services_strategy() -> strategies.SearchStrategy[
    _types.VaultConfigServicesSettings
]:
    """Return a strategy to build incomplete service configurations."""
    return SERVICES_STRATEGY


def assemble_config(
    global_data: _types.VaultConfigGlobalSettings,
    service_data: list[tuple[str, _types.VaultConfigServicesSettings]],
) -> _types.VaultConfig:
    """Return a vault config using the global and service data."""
    services_dict = dict(service_data)
    return (
        {"global": global_data, "services": services_dict}
        if global_data
        else {"services": services_dict}
    )


@strategies.composite
def draw_service_name_and_data(
    draw: hypothesis.strategies.DrawFn,
    num_entries: int,
) -> tuple[tuple[str, _types.VaultConfigServicesSettings], ...]:
    """Draw a service name and settings, as a hypothesis strategy.

    Will draw service names from [`KNOWN_SERVICES`][] and service
    settings via [`services_strategy`][].

    Args:
        draw:
            The `draw` function, as provided for by hypothesis.
        num_entries:
            The number of services to draw.

    Returns:
        A sequence of pairs of service names and service settings.

    """
    possible_services = list(KNOWN_SERVICES)
    selected_services: list[str] = []
    for _ in range(num_entries):
        selected_services.append(
            draw(strategies.sampled_from(possible_services))
        )
        possible_services.remove(selected_services[-1])
    return tuple(
        (service, draw(services_strategy())) for service in selected_services
    )


VAULT_FULL_CONFIG = strategies.builds(
    assemble_config,
    services_strategy(),
    strategies.integers(
        min_value=2,
        max_value=4,
    ).flatmap(draw_service_name_and_data),
)
"""A hypothesis strategy to build full vault configurations."""


def vault_full_config() -> strategies.SearchStrategy[_types.VaultConfig]:
    """Return a strategy to build full vault configurations."""
    return VAULT_FULL_CONFIG


class ConfigManagementStateMachine(stateful.RuleBasedStateMachine):
    """A state machine recording changes in the vault configuration.

    Record possible configuration states in bundles, then in each rule,
    take a configuration and manipulate it somehow.

    Attributes:
        setting:
            A bundle for single-service settings.
        configuration:
            A bundle for full vault configurations.

    """

    def __init__(self) -> None:
        """Initialize self, set up context managers and enter them."""
        super().__init__()
        self.runner = machinery.CliRunner(mix_stderr=False)
        self.exit_stack = contextlib.ExitStack().__enter__()
        self.monkeypatch = self.exit_stack.enter_context(
            pytest.MonkeyPatch().context()
        )
        self.isolated_config = self.exit_stack.enter_context(
            pytest_machinery.isolated_vault_config(
                monkeypatch=self.monkeypatch,
                runner=self.runner,
                vault_config={"services": {}},
            )
        )

    setting: stateful.Bundle[_types.VaultConfigServicesSettings] = (
        stateful.Bundle("setting")
    )
    """"""
    configuration: stateful.Bundle[_types.VaultConfig] = stateful.Bundle(
        "configuration"
    )
    """"""

    @stateful.initialize(
        target=configuration,
        configs=strategies.lists(
            vault_full_config(),
            min_size=8,
            max_size=8,
        ),
    )
    def declare_initial_configs(
        self,
        configs: Iterable[_types.VaultConfig],
    ) -> stateful.MultipleResults[_types.VaultConfig]:
        """Initialize the configuration bundle with eight configurations."""
        return stateful.multiple(*configs)

    @stateful.initialize(
        target=setting,
        configs=strategies.lists(
            vault_full_config(),
            min_size=4,
            max_size=4,
        ),
    )
    def extract_initial_settings(
        self,
        configs: list[_types.VaultConfig],
    ) -> stateful.MultipleResults[_types.VaultConfigServicesSettings]:
        """Initialize the settings bundle with four service settings."""
        settings: list[_types.VaultConfigServicesSettings] = []
        for c in configs:
            settings.extend(c["services"].values())
        return stateful.multiple(*map(copy.deepcopy, settings))

    @staticmethod
    def fold_configs(
        c1: _types.VaultConfig, c2: _types.VaultConfig
    ) -> _types.VaultConfig:
        """Fold `c1` into `c2`, overriding the latter."""
        new_global_dict = c1.get("global", c2.get("global"))
        if new_global_dict is not None:
            return {
                "global": new_global_dict,
                "services": {**c2["services"], **c1["services"]},
            }
        return {
            "services": {**c2["services"], **c1["services"]},
        }

    @stateful.rule(
        target=configuration,
        config=configuration,
        setting=setting.filter(bool),
        maybe_unset=strategies.sets(
            strategies.sampled_from(VALID_PROPERTIES),
            max_size=3,
        ),
        overwrite=strategies.booleans(),
    )
    def set_globals(
        self,
        config: _types.VaultConfig,
        setting: _types.VaultConfigGlobalSettings,
        maybe_unset: set[str],
        overwrite: bool,
    ) -> _types.VaultConfig:
        """Set the global settings of a configuration.

        Args:
            config:
                The configuration to edit.
            setting:
                The new global settings.
            maybe_unset:
                Settings keys to additionally unset, if not already
                present in the new settings.  Corresponds to the
                `--unset` command-line argument.
            overwrite:
                Overwrite the settings object if true, or merge if
                false.  Corresponds to the `--overwrite-existing` and
                `--merge-existing` command-line arguments.

        Returns:
            The amended configuration.

        """
        cli_helpers.save_config(config)
        config_global = config.get("global", {})
        maybe_unset = set(maybe_unset) - setting.keys()
        if overwrite:
            config["global"] = config_global = {}
        elif maybe_unset:
            for key in maybe_unset:
                config_global.pop(key, None)  # type: ignore[misc]
        config.setdefault("global", {}).update(setting)
        assert _types.is_vault_config(config)
        # NOTE: This relies on settings_obj containing only the keys
        # "length", "repeat", "upper", "lower", "number", "space",
        # "dash" and "symbol".
        result = self.runner.invoke(
            cli.derivepassphrase_vault,
            [
                "--config",
                "--overwrite-existing" if overwrite else "--merge-existing",
            ]
            + [f"--unset={key}" for key in maybe_unset]
            + [
                f"--{key}={value}"
                for key, value in setting.items()
                if key in VALID_PROPERTIES
            ],
            catch_exceptions=False,
        )
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        config=configuration,
        service=strategies.sampled_from(KNOWN_SERVICES),
        setting=setting.filter(bool),
        maybe_unset=strategies.sets(
            strategies.sampled_from(VALID_PROPERTIES),
            max_size=3,
        ),
        overwrite=strategies.booleans(),
    )
    def set_service(
        self,
        config: _types.VaultConfig,
        service: str,
        setting: _types.VaultConfigServicesSettings,
        maybe_unset: set[str],
        overwrite: bool,
    ) -> _types.VaultConfig:
        """Set the named service settings for a configuration.

        Args:
            config:
                The configuration to edit.
            service:
                The name of the service to set.
            setting:
                The new service settings.
            maybe_unset:
                Settings keys to additionally unset, if not already
                present in the new settings.  Corresponds to the
                `--unset` command-line argument.
            overwrite:
                Overwrite the settings object if true, or merge if
                false.  Corresponds to the `--overwrite-existing` and
                `--merge-existing` command-line arguments.

        Returns:
            The amended configuration.

        """
        cli_helpers.save_config(config)
        config_service = config["services"].get(service, {})
        maybe_unset = set(maybe_unset) - setting.keys()
        if overwrite:
            config["services"][service] = config_service = {}
        elif maybe_unset:
            for key in maybe_unset:
                config_service.pop(key, None)  # type: ignore[misc]
        config["services"].setdefault(service, {}).update(setting)
        assert _types.is_vault_config(config)
        # NOTE: This relies on settings_obj containing only the keys
        # "length", "repeat", "upper", "lower", "number", "space",
        # "dash" and "symbol".
        result = self.runner.invoke(
            cli.derivepassphrase_vault,
            [
                "--config",
                "--overwrite-existing" if overwrite else "--merge-existing",
            ]
            + [f"--unset={key}" for key in maybe_unset]
            + [
                f"--{key}={value}"
                for key, value in setting.items()
                if key in VALID_PROPERTIES
            ]
            + ["--", service],
            catch_exceptions=False,
        )
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        config=configuration,
    )
    def purge_global(
        self,
        config: _types.VaultConfig,
    ) -> _types.VaultConfig:
        """Purge the globals of a configuration.

        Args:
            config:
                The configuration to edit.

        Returns:
            The pruned configuration.

        """
        cli_helpers.save_config(config)
        config.pop("global", None)
        result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ["--delete-globals"],
            input="y",
            catch_exceptions=False,
        )
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        config_and_service=configuration.filter(
            lambda c: bool(c["services"])
        ).flatmap(
            lambda c: strategies.tuples(
                strategies.just(c),
                strategies.sampled_from(tuple(c["services"].keys())),
            )
        ),
    )
    def purge_service(
        self,
        config_and_service: tuple[_types.VaultConfig, str],
    ) -> _types.VaultConfig:
        """Purge the settings of a named service in a configuration.

        Args:
            config_and_service:
                A 2-tuple containing the configuration to edit, and the
                service name to purge.

        Returns:
            The pruned configuration.

        """
        config, service = config_and_service
        cli_helpers.save_config(config)
        config["services"].pop(service, None)
        result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ["--delete", "--", service],
            input="y",
            catch_exceptions=False,
        )
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        config=configuration,
    )
    def purge_all(
        self,
        config: _types.VaultConfig,
    ) -> _types.VaultConfig:
        """Purge the entire configuration.

        Args:
            config:
                The configuration to edit.

        Returns:
            The empty configuration.

        """
        cli_helpers.save_config(config)
        config = {"services": {}}
        result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ["--clear"],
            input="y",
            catch_exceptions=False,
        )
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        base_config=configuration,
        config_to_import=configuration,
        overwrite=strategies.booleans(),
    )
    def import_configuration(
        self,
        base_config: _types.VaultConfig,
        config_to_import: _types.VaultConfig,
        overwrite: bool,
    ) -> _types.VaultConfig:
        """Import the given configuration into a base configuration.

        Args:
            base_config:
                The configuration to import into.
            config_to_import:
                The configuration to import.
            overwrite:
                Overwrite the base configuration if true, or merge if
                false.  Corresponds to the `--overwrite-existing` and
                `--merge-existing` command-line arguments.

        Returns:
            The imported or merged configuration.

        """
        cli_helpers.save_config(base_config)
        config = (
            self.fold_configs(config_to_import, base_config)
            if not overwrite
            else config_to_import
        )
        assert _types.is_vault_config(config)
        result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ["--import", "-"]
            + (["--overwrite-existing"] if overwrite else []),
            input=json.dumps(config_to_import),
            catch_exceptions=False,
        )
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
        return config

    def teardown(self) -> None:
        """Upon teardown, exit all contexts entered in `__init__`."""
        self.exit_stack.close()


TestConfigManagement = ConfigManagementStateMachine.TestCase
"""The [`unittest.TestCase`][] class that will actually be run."""


class FakeConfigurationMutexAction(NamedTuple):
    """An action/a step in the [`FakeConfigurationMutexStateMachine`][].

    Attributes:
        command_line:
            The command-line for `derivepassphrase vault` to execute.
        input:
            The input to this command.

    """

    command_line: list[str]
    """"""
    input: str | bytes | None = None
    """"""


def run_actions_handler(
    id_num: int,
    action: FakeConfigurationMutexAction,
    *,
    input_queue: queue.Queue,
    output_queue: queue.Queue,
    timeout: int,
) -> None:
    """Prepare the faked mutex, then run `action`.

    This is a top-level handler function -- to be used in a new
    [`multiprocessing.Process`][] -- to run a single action from the
    [`FakeConfigurationMutexStateMachine`][].  Output from this function
    must be sent down the output queue instead of relying on the call
    stack.  Additionally, because this runs in a separate process, we
    need to restart coverage tracking if it is currently running.

    Args:
        id_num:
            The internal ID of this subprocess.
        action:
            The action to execute.
        input_queue:
            The queue for data passed from the manager/parent process to
            this subprocess.
        output_queue:
            The queue for data passed from this subprocess to the
            manager/parent process.
        timeout:
            The maximum amount of time to wait for a data transfer along
            the input or the output queue.  If exceeded, we exit
            immediately.

    """
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            cli_helpers,
            "configuration_mutex",
            lambda: FakeConfigurationMutexStateMachine.ConfigurationMutexStub(
                my_id=id_num,
                input_queue=input_queue,
                output_queue=output_queue,
                timeout=timeout,
            ),
        )
        runner = machinery.CliRunner(mix_stderr=False)
        try:
            result = runner.invoke(
                cli.derivepassphrase_vault,
                args=action.command_line,
                input=action.input,
                catch_exceptions=True,
            )
            output_queue.put(
                FakeConfigurationMutexStateMachine.IPCMessage(
                    id_num,
                    "result",
                    (
                        result.clean_exit(empty_stderr=False),
                        copy.copy(result.stdout),
                        copy.copy(result.stderr),
                    ),
                ),
                block=True,
                timeout=timeout,
            )
        except Exception as exc:  # pragma: no cover  # noqa: BLE001
            output_queue.put(
                FakeConfigurationMutexStateMachine.IPCMessage(
                    id_num, "exception", exc
                ),
                block=False,
            )


@hypothesis.settings(
    stateful_step_count=hypothesis_machinery.get_concurrency_step_count(),
    deadline=None,
)
class FakeConfigurationMutexStateMachine(stateful.RuleBasedStateMachine):
    """A state machine simulating the (faked) configuration mutex.

    Generate an ordered set of concurrent writers to the
    derivepassphrase configuration, then test that the writers' accesses
    are serialized correctly, i.e., test that the writers correctly use
    the mutex to avoid concurrent accesses, under the assumption that
    the mutex itself is correctly implemented.

    We use a custom mutex implementation to both ensure that all writers
    attempt to lock the configuration at the same time and that the lock
    is granted in our desired order.  This test is therefore independent
    of the actual (operating system-specific) mutex implementation in
    `derivepassphrase`.

    Attributes:
        setting:
            A bundle for single-service settings.
        configuration:
            A bundle for full vault configurations.

    """

    class IPCMessage(NamedTuple):
        """A message for inter-process communication.

        Used by the configuration mutex stub class to affect/signal the
        control flow amongst the linked mutex clients.

        Attributes:
            child_id:
                The ID of the sending or receiving child process.
            message:
                One of "ready", "go", "config", "result" or "exception".
            payload:
                The (optional) message payload.

        """

        child_id: int
        """"""
        message: Literal["ready", "go", "config", "result", "exception"]
        """"""
        payload: object | None
        """"""

    class ConfigurationMutexStub(cli_helpers.ConfigurationMutex):
        """Configuration mutex subclass that enforces a locking order.

        Each configuration mutex stub object ("mutex client") has an
        associated ID, and one read-only and one write-only pipe
        (actually: [`multiprocessing.Queue`][] objects) to the "manager"
        instance coordinating these stub objects.  First, the mutex
        client signals readiness, then the manager signals when the
        mutex shall be considered "acquired", then finally the mutex
        client sends the result back (simultaneously releasing the mutex
        again).  The manager may optionally send an abort signal if the
        operations take too long.

        This subclass also copies the effective vault configuration
        to `intermediate_configs` upon releasing the lock.

        """

        def __init__(
            self,
            *,
            my_id: int,
            timeout: int,
            input_queue: queue.Queue[
                FakeConfigurationMutexStateMachine.IPCMessage
            ],
            output_queue: queue.Queue[
                FakeConfigurationMutexStateMachine.IPCMessage
            ],
        ) -> None:
            """Initialize this mutex client.

            Args:
                my_id:
                    The ID of this client.
                timeout:
                    The timeout for each get and put operation on the
                    queues.
                input_queue:
                    The message queue for IPC messages from the manager
                    instance to this mutex client.
                output_queue:
                    The message queue for IPC messages from this mutex
                    client to the manager instance.

            """
            super().__init__()

            def lock() -> None:
                """Simulate locking of the mutex.

                Issue a "ready" message, wait for a "go", then return.
                If an exception occurs, issue an "exception" message,
                then raise the exception.

                """
                IPCMessage: TypeAlias = (
                    FakeConfigurationMutexStateMachine.IPCMessage
                )
                try:
                    output_queue.put(
                        IPCMessage(my_id, "ready", None),
                        block=True,
                        timeout=timeout,
                    )
                    ok = input_queue.get(block=True, timeout=timeout)
                    if ok != IPCMessage(my_id, "go", None):  # pragma: no cover
                        output_queue.put(
                            IPCMessage(my_id, "exception", ok), block=False
                        )
                        raise (
                            ok[2]
                            if isinstance(ok[2], BaseException)
                            else RuntimeError(ok[2])
                        )
                except (queue.Empty, queue.Full) as exc:  # pragma: no cover
                    output_queue.put(
                        IPCMessage(my_id, "exception", exc), block=False
                    )
                    return

            def unlock() -> None:
                """Simulate unlocking of the mutex.

                Issue a "config" message, then return.  If an exception
                occurs, issue an "exception" message, then raise the
                exception.

                """
                IPCMessage: TypeAlias = (
                    FakeConfigurationMutexStateMachine.IPCMessage
                )
                try:
                    output_queue.put(
                        IPCMessage(
                            my_id,
                            "config",
                            copy.copy(cli_helpers.load_config()),
                        ),
                        block=True,
                        timeout=timeout,
                    )
                except (queue.Empty, queue.Full) as exc:  # pragma: no cover
                    output_queue.put(
                        IPCMessage(my_id, "exception", exc), block=False
                    )
                    raise

            self.lock = lock
            self.unlock = unlock

    setting: stateful.Bundle[_types.VaultConfigServicesSettings] = (
        stateful.Bundle("setting")
    )
    """"""
    configuration: stateful.Bundle[_types.VaultConfig] = stateful.Bundle(
        "configuration"
    )
    """"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the state machine."""
        super().__init__(*args, **kwargs)
        self.actions: list[FakeConfigurationMutexAction] = []
        # Determine the step count by poking around in the hypothesis
        # internals. As this isn't guaranteed to be stable, turn off
        # coverage.
        try:  # pragma: no cover
            settings: hypothesis.settings | None
            settings = FakeConfigurationMutexStateMachine.TestCase.settings
        except AttributeError:  # pragma: no cover
            settings = None
        self.step_count = (
            hypothesis_machinery.get_concurrency_step_count(settings)
        )

    @stateful.initialize(
        target=configuration,
        configs=strategies.lists(
            vault_full_config(),
            min_size=8,
            max_size=8,
        ),
    )
    def declare_initial_configs(
        self,
        configs: list[_types.VaultConfig],
    ) -> stateful.MultipleResults[_types.VaultConfig]:
        """Initialize the configuration bundle with eight configurations."""
        return stateful.multiple(*configs)

    @stateful.initialize(
        target=setting,
        configs=strategies.lists(
            vault_full_config(),
            min_size=4,
            max_size=4,
        ),
    )
    def extract_initial_settings(
        self,
        configs: list[_types.VaultConfig],
    ) -> stateful.MultipleResults[_types.VaultConfigServicesSettings]:
        """Initialize the settings bundle with four service settings."""
        settings: list[_types.VaultConfigServicesSettings] = []
        for c in configs:
            settings.extend(c["services"].values())
        return stateful.multiple(*map(copy.deepcopy, settings))

    @stateful.initialize(
        config=vault_full_config(),
    )
    def declare_initial_action(
        self,
        config: _types.VaultConfig,
    ) -> None:
        """Initialize the actions bundle from the configuration bundle.

        This is roughly comparable to the
        [`add_import_configuration_action`][] general rule, but adding
        it as a separate initialize rule avoids having to guard every
        other action-amending rule against empty action sequences, which
        would discard huge portions of the rule selection search space
        and thus trigger loads of hypothesis health check warnings.

        """
        command_line = ["--import", "-", "--overwrite-existing"]
        input = json.dumps(config)  # noqa: A001
        hypothesis.note(f"# {command_line = }, {input = }")
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule(
        setting=setting.filter(bool),
        maybe_unset=strategies.sets(
            strategies.sampled_from(VALID_PROPERTIES),
            max_size=3,
        ),
        overwrite=strategies.booleans(),
    )
    def add_set_globals_action(
        self,
        setting: _types.VaultConfigGlobalSettings,
        maybe_unset: set[str],
        overwrite: bool,
    ) -> None:
        """Set the global settings of a configuration.

        Args:
            setting:
                The new global settings.
            maybe_unset:
                Settings keys to additionally unset, if not already
                present in the new settings.  Corresponds to the
                `--unset` command-line argument.
            overwrite:
                Overwrite the settings object if true, or merge if
                false.  Corresponds to the `--overwrite-existing` and
                `--merge-existing` command-line arguments.

        """
        maybe_unset = set(maybe_unset) - setting.keys()
        command_line = (
            [
                "--config",
                "--overwrite-existing" if overwrite else "--merge-existing",
            ]
            + [f"--unset={key}" for key in maybe_unset]
            + [
                f"--{key}={value}"
                for key, value in setting.items()
                if key in VALID_PROPERTIES
            ]
        )
        input = None  # noqa: A001
        hypothesis.note(f"# {command_line = }, {input = }")
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule(
        service=strategies.sampled_from(KNOWN_SERVICES),
        setting=setting.filter(bool),
        maybe_unset=strategies.sets(
            strategies.sampled_from(VALID_PROPERTIES),
            max_size=3,
        ),
        overwrite=strategies.booleans(),
    )
    def add_set_service_action(
        self,
        service: str,
        setting: _types.VaultConfigServicesSettings,
        maybe_unset: set[str],
        overwrite: bool,
    ) -> None:
        """Set the named service settings for a configuration.

        Args:
            service:
                The name of the service to set.
            setting:
                The new service settings.
            maybe_unset:
                Settings keys to additionally unset, if not already
                present in the new settings.  Corresponds to the
                `--unset` command-line argument.
            overwrite:
                Overwrite the settings object if true, or merge if
                false.  Corresponds to the `--overwrite-existing` and
                `--merge-existing` command-line arguments.

        """
        maybe_unset = set(maybe_unset) - setting.keys()
        command_line = (
            [
                "--config",
                "--overwrite-existing" if overwrite else "--merge-existing",
            ]
            + [f"--unset={key}" for key in maybe_unset]
            + [
                f"--{key}={value}"
                for key, value in setting.items()
                if key in VALID_PROPERTIES
            ]
            + ["--", service]
        )
        input = None  # noqa: A001
        hypothesis.note(f"# {command_line = }, {input = }")
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule()
    def add_purge_global_action(
        self,
    ) -> None:
        """Purge the globals of a configuration."""
        command_line = ["--delete-globals"]
        input = None  # 'y'  # noqa: A001
        hypothesis.note(f"# {command_line = }, {input = }")
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule(
        service=strategies.sampled_from(KNOWN_SERVICES),
    )
    def add_purge_service_action(
        self,
        service: str,
    ) -> None:
        """Purge the settings of a named service in a configuration.

        Args:
            service:
                The service name to purge.

        """
        command_line = ["--delete", "--", service]
        input = None  # 'y'  # noqa: A001
        hypothesis.note(f"# {command_line = }, {input = }")
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule()
    def add_purge_all_action(
        self,
    ) -> None:
        """Purge the entire configuration."""
        command_line = ["--clear"]
        input = None  # 'y'  # noqa: A001
        hypothesis.note(f"# {command_line = }, {input = }")
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule(
        config_to_import=configuration,
        overwrite=strategies.booleans(),
    )
    def add_import_configuration_action(
        self,
        config_to_import: _types.VaultConfig,
        overwrite: bool,
    ) -> None:
        """Import the given configuration.

        Args:
            config_to_import:
                The configuration to import.
            overwrite:
                Overwrite the base configuration if true, or merge if
                false.  Corresponds to the `--overwrite-existing` and
                `--merge-existing` command-line arguments.

        """
        command_line = ["--import", "-"] + (
            ["--overwrite-existing"] if overwrite else []
        )
        input = json.dumps(config_to_import)  # noqa: A001
        hypothesis.note(f"# {command_line = }, {input = }")
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.precondition(lambda self: len(self.actions) > 0)
    @stateful.invariant()
    def run_actions(  # noqa: C901
        self,
    ) -> None:
        """Run the actions, serially and concurrently.

        Run the actions once serially, then once more concurrently with
        the faked configuration mutex, and assert that both runs yield
        identical intermediate and final results.

        We must run the concurrent version in processes, not threads or
        Python async functions, because the `click` testing machinery
        manipulates global properties (e.g. the standard I/O streams,
        the current directory, and the environment), and we require this
        manipulation to happen in a time-overlapped manner.

        However, running multiple processes increases the risk of the
        operating system imposing process count or memory limits on us.
        We therefore skip the test as a whole if we fail to start a new
        process due to lack of necessary resources (memory, processes,
        or open file descriptors).

        """
        if not TYPE_CHECKING:  # pragma: no branch
            multiprocessing = pytest.importorskip("multiprocessing")
        IPCMessage: TypeAlias = FakeConfigurationMutexStateMachine.IPCMessage
        intermediate_configs: dict[int, _types.VaultConfig] = {}
        intermediate_results: dict[
            int, tuple[bool, str | None, str | None]
        ] = {}
        true_configs: dict[int, _types.VaultConfig] = {}
        true_results: dict[int, tuple[bool, str | None, str | None]] = {}
        timeout = 30  # Hopefully slow enough to accomodate The Annoying OS.
        actions = self.actions
        mp = multiprocessing.get_context()
        # Coverage tracking writes coverage data to the current working
        # directory, but because the subprocesses are spawned within the
        # `pytest_machinery.isolated_vault_config` context manager, their starting
        # working directory is the isolated one, not the original one.
        orig_cwd = pathlib.Path.cwd()

        fatal_process_creation_errnos = {
            # Specified by POSIX for fork(3).
            errno.ENOMEM,
            # Specified by POSIX for fork(3).
            errno.EAGAIN,
            # Specified by Linux/glibc for fork(3)
            getattr(errno, "ENOSYS", errno.ENOMEM),
            # Specified by POSIX for posix_spawn(3).
            errno.EINVAL,
        }

        hypothesis.note(f"# {actions = }")

        stack = contextlib.ExitStack()
        with stack:
            runner = machinery.CliRunner(mix_stderr=False)
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={"services": {}},
                )
            )
            for i, action in enumerate(actions):
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    args=action.command_line,
                    input=action.input,
                    catch_exceptions=True,
                )
                true_configs[i] = copy.copy(cli_helpers.load_config())
                true_results[i] = (
                    result.clean_exit(empty_stderr=False),
                    result.stdout,
                    result.stderr,
                )

        with stack:  # noqa: PLR1702
            runner = machinery.CliRunner(mix_stderr=False)
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={"services": {}},
                )
            )

            child_output_queue: multiprocessing.Queue[IPCMessage] = mp.Queue()
            child_input_queues: list[
                multiprocessing.Queue[IPCMessage] | None
            ] = []
            processes: list[multiprocessing.process.BaseProcess] = []
            processes_pending: set[multiprocessing.process.BaseProcess] = set()
            ready_wait: set[int] = set()

            try:
                for i, action in enumerate(actions):
                    q: multiprocessing.Queue[IPCMessage] | None = mp.Queue()
                    try:
                        p: multiprocessing.process.BaseProcess = mp.Process(
                            name=f"fake-mutex-action-{i:02d}",
                            target=run_actions_handler,
                            kwargs={
                                "id_num": i,
                                "timeout": timeout,
                                "action": action,
                                "input_queue": q,
                                "output_queue": child_output_queue,
                            },
                            daemon=False,
                        )
                        p.start()
                    except OSError as exc:  # pragma: no cover
                        if exc.errno in fatal_process_creation_errnos:
                            pytest.skip(
                                "cannot test mutex functionality due to "
                                "lack of system resources for "
                                "creating enough subprocesses"
                            )
                        raise
                    else:
                        processes.append(p)
                        processes_pending.add(p)
                        child_input_queues.append(q)
                        ready_wait.add(i)

                while processes_pending:
                    try:
                        self.mainloop(
                            timeout=timeout,
                            child_output_queue=child_output_queue,
                            child_input_queues=child_input_queues,
                            ready_wait=ready_wait,
                            intermediate_configs=intermediate_configs,
                            intermediate_results=intermediate_results,
                            processes=processes,
                            processes_pending=processes_pending,
                            block=True,
                        )
                    except Exception as exc:  # pragma: no cover
                        for i, q in enumerate(child_input_queues):
                            if q:
                                q.put(IPCMessage(i, "exception", exc))
                        for p in processes_pending:
                            p.join(timeout=timeout)
                        raise
            finally:
                try:
                    while True:
                        try:
                            self.mainloop(
                                timeout=timeout,
                                child_output_queue=child_output_queue,
                                child_input_queues=child_input_queues,
                                ready_wait=ready_wait,
                                intermediate_configs=intermediate_configs,
                                intermediate_results=intermediate_results,
                                processes=processes,
                                processes_pending=processes_pending,
                                block=False,
                            )
                        except queue.Empty:
                            break
                finally:
                    # The subprocesses have this
                    # `pytest_machinery.isolated_vault_config` directory as their
                    # startup and working directory, so systems like
                    # coverage tracking write their data files to this
                    # directory.  We need to manually move them back to
                    # the starting working directory if they are to
                    # survive this test.
                    for coverage_file in pathlib.Path.cwd().glob(
                        ".coverage.*"
                    ):
                        shutil.move(coverage_file, orig_cwd)
        hypothesis.note(
            f"# {true_results = }, {intermediate_results = }, "
            f"identical = {true_results == intermediate_results}"
        )
        hypothesis.note(
            f"# {true_configs = }, {intermediate_configs = }, "
            f"identical = {true_configs == intermediate_configs}"
        )
        assert intermediate_results == true_results
        assert intermediate_configs == true_configs

    @staticmethod
    def mainloop(
        *,
        timeout: int,
        child_output_queue: multiprocessing.Queue[
            FakeConfigurationMutexStateMachine.IPCMessage
        ],
        child_input_queues: list[
            multiprocessing.Queue[
                FakeConfigurationMutexStateMachine.IPCMessage
            ]
            | None
        ],
        ready_wait: set[int],
        intermediate_configs: dict[int, _types.VaultConfig],
        intermediate_results: dict[int, tuple[bool, str | None, str | None]],
        processes: list[multiprocessing.process.BaseProcess],
        processes_pending: set[multiprocessing.process.BaseProcess],
        block: bool = True,
    ) -> None:
        IPCMessage: TypeAlias = FakeConfigurationMutexStateMachine.IPCMessage
        msg = child_output_queue.get(block=block, timeout=timeout)
        # TODO(the-13th-letter): Rewrite using structural pattern
        # matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        if (  # pragma: no cover
            isinstance(msg, IPCMessage)
            and msg[1] == "exception"
            and isinstance(msg[2], Exception)
        ):
            e = msg[2]
            raise e
        if isinstance(msg, IPCMessage) and msg[1] == "ready":
            n = msg[0]
            ready_wait.remove(n)
            if not ready_wait:
                assert child_input_queues
                assert child_input_queues[0]
                child_input_queues[0].put(
                    IPCMessage(0, "go", None),
                    block=True,
                    timeout=timeout,
                )
        elif isinstance(msg, IPCMessage) and msg[1] == "config":
            n = msg[0]
            config = msg[2]
            intermediate_configs[n] = cast("_types.VaultConfig", config)
        elif isinstance(msg, IPCMessage) and msg[1] == "result":
            n = msg[0]
            result_ = msg[2]
            result_tuple: tuple[bool, str | None, str | None] = cast(
                "tuple[bool, str | None, str | None]", result_
            )
            intermediate_results[n] = result_tuple
            child_input_queues[n] = None
            p = processes[n]
            p.join(timeout=timeout)
            assert not p.is_alive()
            processes_pending.remove(p)
            assert result_tuple[0], (
                f"action #{n} exited with an error: {result_tuple!r}"
            )
            if n + 1 < len(processes):
                next_child_input_queue = child_input_queues[n + 1]
                assert next_child_input_queue
                next_child_input_queue.put(
                    IPCMessage(n + 1, "go", None),
                    block=True,
                    timeout=timeout,
                )
        else:
            raise AssertionError()


TestFakedConfigurationMutex = (
    pytest_machinery.skip_if_no_multiprocessing_support(
        FakeConfigurationMutexStateMachine.TestCase
    )
)
"""The [`unittest.TestCase`][] class that will actually be run."""
