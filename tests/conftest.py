# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import base64
import contextlib
import ctypes
import datetime
import importlib
import importlib.util
import os
import shutil
import socket
import subprocess
import sys
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

import hypothesis
import packaging.version
import pytest
from typing_extensions import NamedTuple

from derivepassphrase import _types, ssh_agent
from derivepassphrase.ssh_agent import socketprovider
from tests import data, machinery
from tests.data import callables

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

startup_ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK", None)


def _hypothesis_settings_setup() -> None:
    """
    Ensure sensible hypothesis settings if running under coverage.

    In our tests, the sys.monitoring tracer slows down execution speed
    by a factor of roughly 3, the C tracer by roughly 2.5, and the
    Python tracer by roughly 40.  Ensure that hypothesis default
    timeouts apply relative to this *new* execution speed, not the old
    one.

    In any case, we *also* reduce the state machine step count to 32
    steps per run, because the current state machines defined in the
    tests rather benefit from broad testing rather than deep testing.

    """
    settings = hypothesis.settings()
    slowdown: float | None = None
    if (
        importlib.util.find_spec("coverage") is not None
        and settings.deadline is not None
        and settings.deadline.total_seconds() < 1.0
    ):  # pragma: no cover [external]
        ctracer_class = (
            importlib.import_module("coverage.tracer").CTracer
            if importlib.util.find_spec("coverage.tracer") is not None
            else type(None)
        )
        pytracer_class = importlib.import_module("coverage.pytracer").PyTracer
        if (
            getattr(sys, "monitoring", None) is not None
            and sys.monitoring.get_tool(sys.monitoring.COVERAGE_ID)
            == "coverage.py"
        ):
            slowdown = 3.0
        elif (
            trace_func := getattr(sys, "gettrace", lambda: None)()
        ) is not None and isinstance(trace_func, ctracer_class):
            slowdown = 2.5
        elif (
            trace_func is not None
            and hasattr(trace_func, "__self__")
            and isinstance(trace_func.__self__, pytracer_class)
        ):
            slowdown = 8.0
    settings = hypothesis.settings(
        deadline=slowdown * settings.deadline
        if slowdown
        else settings.deadline,
        stateful_step_count=32,
        suppress_health_check=(hypothesis.HealthCheck.too_slow,),
    )
    hypothesis.settings.register_profile("default", settings)
    hypothesis.settings.register_profile(
        "dev", derandomize=True, max_examples=10
    )
    hypothesis.settings.register_profile(
        "debug",
        parent=hypothesis.settings.get_profile("dev"),
        verbosity=hypothesis.Verbosity.verbose,
    )
    hypothesis.settings.register_profile(
        "flaky",
        deadline=(
            settings.deadline - settings.deadline // 4
            if settings.deadline is not None
            else datetime.timedelta(milliseconds=150)
        ),
    )
    ci_profile = hypothesis.settings.get_profile("ci")
    hypothesis.settings.register_profile(
        "intense",
        parent=ci_profile,
        derandomize=False,
        max_examples=10 * ci_profile.max_examples,
    )


_hypothesis_settings_setup()


def pytest_configure(config: pytest.Config) -> None:
    """Configure `pytest`: add the `heavy_duty` marker."""
    config.addinivalue_line(
        "markers",
        (
            "heavy_duty: "
            "mark test as a slow, heavy-duty test (e.g., an integration test)"
        ),
    )


# https://docs.pytest.org/en/stable/explanation/fixtures.html#a-note-about-fixture-cleanup
# https://github.com/pytest-dev/pytest/issues/5243#issuecomment-491522595
@pytest.fixture(scope="session", autouse=False)
def term_handler() -> Iterator[None]:  # pragma: no cover [external]
    try:
        import signal  # noqa: PLC0415

        sigint_handler = signal.getsignal(signal.SIGINT)
    except (ImportError, OSError):
        return
    else:
        orig_term = signal.signal(signal.SIGTERM, sigint_handler)
        yield
        signal.signal(signal.SIGTERM, orig_term)


@pytest.fixture(scope="session")
def skip_if_no_af_unix_support() -> None:  # pragma: no cover [external]
    """Skip the test if Python does not support AF_UNIX.

    Implemented as a fixture instead of a mark because it has
    consequences for other fixtures, and because another "autouse"
    session fixture may want to force/simulate non-support of
    [`socket.AF_UNIX`][].

    """
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("No Python or system support for UNIX domain sockets.")


class SSHAgentSpawnFunc(Protocol):
    """Spawns an SSH agent, if possible."""

    def __call__(
        self,
        executable: str | None,
        env: dict[str, str],
    ) -> subprocess.Popen[str] | None:
        """Spawn the SSH agent.

        Args:
            executable:
                The respective SSH agent executable.
            env:
                The new environment for the respective agent.  Should
                typically not include an SSH_AUTH_SOCK variable.

        Returns:
            The spawned SSH agent subprocess.  If the executable is
            `None`, then return `None` directly.

            It is the caller's responsibility to clean up the spawned
            subprocess.

        Raises:
            OSError:
                The [`subprocess.Popen`][] call failed.  See there.

        """


class SSHAgentInterfaceFunc(Protocol):
    """Interface an SSH agent, if possible."""

    def __call__(
        self,
        executable: str | None,
        env: dict[str, Any],
    ) -> _types.SSHAgentSocket | None:
        """Interface the SSH agent.

        Args:
            env:
                A configuration environment to interface the agent.
                Will typically include some kind of address setting
                detailing how to communicate with the agent.  The
                exact contents depend on the specific agent.

        Other Args:
            executable:
                (Ignored.  Not relevant for interfacing functions.)

        Returns:
            An abstract socket connected to the specified SSH agent, if
            possible; otherwise, `None`.

            It is the caller's responsibility to clean up the socket
            (through use of the context manager protocol).

        """


def spawn_pageant_on_posix(  # pragma: no cover [external]
    executable: str | None, env: dict[str, str]
) -> subprocess.Popen[str] | None:
    """Spawn an isolated (UNIX) Pageant, if possible.

    We attempt to detect whether Pageant is usable, i.e. whether Pageant
    has output buffering problems when announcing its authentication
    socket.  This is the case for Pageant 0.81 and earlier.

    Args:
        executable:
            The path to the Pageant executable.
        env:
            The new environment for Pageant.  Should typically not
            include an SSH_AUTH_SOCK variable.

    Returns:
        The spawned Pageant subprocess.  If the executable is `None`, or
        if we detect that Pageant cannot be sensibly controlled as
        a subprocess, then return `None` directly.

        It is the caller's responsibility to clean up the spawned
        subprocess.

    """
    if os.name == "nt":  # pragma: no cover [external]
        return None
    if executable is None:  # pragma: no cover [external]
        executable = shutil.which("pageant")
        if executable is None:
            return None

    # Apparently, Pageant 0.81 and lower running in debug mode does
    # not actively flush its output.  As a result, the first two
    # lines, which set the SSH_AUTH_SOCK and the SSH_AGENT_PID, only
    # print once the output buffer is flushed, whenever that is.
    #
    # This has been reported to the PuTTY developers.  It is fixed in
    # version 0.82, though the PuTTY developers consider this to be an
    # abuse of debug mode.  A new foreground mode (`--foreground`), also
    # introduced in 0.82, provides the desired behavior: no forking, and
    # immediately parsable instructions for SSH_AUTH_SOCK and
    # SSH_AGENT_PID.

    help_output = subprocess.run(
        ["pageant", "--help"],
        executable=executable,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    help_lines = help_output.splitlines(True)
    pageant_version_string = (
        help_lines[1].strip().removeprefix("Release ")
        if len(help_lines) >= 2
        else ""
    )
    v0_82 = packaging.version.Version("0.82")
    pageant_version = packaging.version.Version(pageant_version_string)

    if pageant_version < v0_82:  # pragma: no cover [external]
        return None

    return subprocess.Popen(
        ["pageant", "--foreground", "-s"],
        executable=executable,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        shell=False,
        env=env,
        text=True,
        bufsize=1,
    )


def spawn_openssh_agent_on_posix(  # pragma: no cover [external]
    executable: str | None, env: dict[str, str]
) -> subprocess.Popen[str] | None:
    """Spawn an isolated OpenSSH agent (on UNIX), if possible.

    Args:
        executable:
            The path to the OpenSSH agent executable.
        env:
            The new environment for the OpenSSH agent.  Should typically
            not include an SSH_AUTH_SOCK variable.

    Returns:
        The spawned OpenSSH agent subprocess.  If the executable is
        `None`, then return `None` directly.

        It is the caller's responsibility to clean up the spawned
        subprocess.

    """
    if os.name == "nt":  # pragma: no cover [external]
        return None
    if executable is None:  # pragma: no cover [external]
        executable = shutil.which("ssh-agent")
        if executable is None:
            return None
    return subprocess.Popen(
        ["ssh-agent", "-D", "-s"],
        executable=executable,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        shell=False,
        env=env,
        text=True,
        bufsize=1,
    )


def spawn_noop(  # pragma: no cover [unused]
    executable: str | None, env: dict[str, str]
) -> None:
    """Placeholder function. Does nothing."""


def interface_pageant_on_the_annoying_os(
    executable: str | None,
    env: dict[str, Any],
) -> _types.SSHAgentSocket | None:  # pragma: no cover [external]
    """Interface a Pageant instance on The Annoying OS, if possible.

    Args:
        env:
            (Ignored.)

    Returns:
        An abstract socket connected to Pageant, if possible; else
        `None`.

        It is the caller's responsibility to clean up the socket
        (through use of the context manager protocol).

    """
    del executable, env
    try:
        return socketprovider.SocketProvider.windows_named_pipe_for_pageant()
    except socketprovider.WindowsNamedPipesNotAvailableError:
        return None


def interface_openssh_agent_on_the_annoying_os(
    executable: str | None,
    env: dict[str, Any],
) -> _types.SSHAgentSocket | None:  # pragma: no cover [external]
    """Interface an OpenSSH agent instance on The Annoying OS, if possible.

    Args:
        env:
            (Ignored.)

    Returns:
        An abstract socket connected to the OpenSSH agent, if possible;
        else `None`.

        It is the caller's responsibility to clean up the socket
        (through use of the context manager protocol).

    """
    del executable, env
    try:
        return socketprovider.SocketProvider.windows_named_pipe_for_openssh()
    except socketprovider.WindowsNamedPipesNotAvailableError:
        return None


class SpawnHandler(NamedTuple):
    """A handler for a spawned or interfaced SSH agent.

    Attributes:
        key:
            The key under which this handler is registered.
        executable:
            The (optional) full path to the executable.
        spawn_func:
            The spawn function.
        agent_type:
            The type of the spawned or interfaced SSH agent.
        agent_name:
            The (optional) display name for this handler.

    """

    key: str
    executable: str | None
    spawn_func: SSHAgentSpawnFunc | SSHAgentInterfaceFunc
    agent_type: data.KnownSSHAgent
    agent_name: str | None


spawn_handlers: dict[str, SpawnHandler] = {
    "unix-pageant": SpawnHandler(
        "unix-pageant",
        None,
        spawn_pageant_on_posix,
        data.KnownSSHAgent.UNIXPageant,
        "Pageant (UNIX)",
    ),
    "openssh": SpawnHandler(
        "openssh",
        None,
        spawn_openssh_agent_on_posix,
        data.KnownSSHAgent.OpenSSHAgent,
        "ssh-agent (OpenSSH)",
    ),
    "pageant": SpawnHandler(
        "pageant",
        None,
        interface_pageant_on_the_annoying_os,
        data.KnownSSHAgent.Pageant,
        "Pageant",
    ),
    "openssh-on-windows": SpawnHandler(
        "openssh-on-windows",
        None,
        interface_openssh_agent_on_the_annoying_os,
        data.KnownSSHAgent.OpenSSHAgentOnWindows,
        "ssh-agent (OpenSSH on Windows)",
    ),
    "stub_agent_with_address": SpawnHandler(
        "stub_agent_with_address",
        None,
        spawn_noop,
        data.KnownSSHAgent.StubbedSSHAgent,
        "stub_agent_with_address (derivepassphrase test suite)",
    ),
    "stub_agent_with_address_and_deterministic_dsa": SpawnHandler(
        "stub_agent_with_address_and_deterministic_dsa",
        None,
        spawn_noop,
        data.KnownSSHAgent.StubbedSSHAgent,
        "stub_agent_with_address_and_deterministic_dsa "
        "(derivepassphrase test suite)",
    ),
    "(system-agent)": SpawnHandler(
        "(system-agent)",
        None,
        spawn_noop,
        data.KnownSSHAgent.UNKNOWN,
        None,
    ),
}
"""
The standard registry of agent spawning functions.
"""


def is_agent_permitted(
    agent_type: data.KnownSSHAgent,
) -> bool:  # pragma: no cover [external]
    """May the given SSH agent be spawned by the test harness?

    If the environment variable `PERMITTED_SSH_AGENTS` is given, it
    names a comma-separated list of known SSH agent names that the test
    harness may spawn.  Invalid names are silently ignored.  If not
    given, or empty, then any agent may be spawned.

    (To not allow any agent to be spawned, specify a single comma as the
    list.  But see below.)

    The stubbed agents cannot be restricted in this manner, as the test
    suite depends on their availability.

    """
    if not os.environ.get("PERMITTED_SSH_AGENTS"):
        return True
    permitted_agents = {data.KnownSSHAgent.StubbedSSHAgent}
    permitted_agents.update({
        data.KnownSSHAgent(x)
        for x in os.environ["PERMITTED_SSH_AGENTS"].split(",")
        if x in data.KnownSSHAgent.__members__
    })
    return agent_type in permitted_agents


spawn_handlers_params: list[Sequence] = []
"""
The standard registry of agent spawning functions, annotated as
a `pytest` parameter set.  (In particular, this includes the conditional
skip marks.)  Used by some test fixtures.
"""
for key, handler in spawn_handlers.items():
    marks = [
        pytest.mark.skipif(
            not is_agent_permitted(handler.agent_type),
            reason="SSH agent excluded via PERMITTED_AGENTS "
            "environment variable.",
        ),
    ]
    # Some agents require UNIX domain socket support.
    if key in {"unix-pageant", "openssh"}:
        marks.append(
            pytest.mark.skipif(
                not hasattr(socket, "AF_UNIX"),
                reason="No Python or system support for UNIX domain sockets.",
            )
        )
    # Others require Windows named pipe support.
    if key in {"pageant", "openssh-on-windows"}:
        marks.append(
            pytest.mark.skipif(
                not hasattr(ctypes, "WinDLL"),
                reason="No Python or system support for Windows named pipes.",
            )
        )
    spawn_handlers_params.append(pytest.param(handler, id=key, marks=marks))


Popen = TypeVar("Popen", bound=subprocess.Popen)


@contextlib.contextmanager
def terminate_on_exit(proc: Popen) -> Iterator[Popen]:
    """Terminate and wait for the subprocess upon exiting the context.

    Args:
        proc:
            The subprocess to manage.

    Returns:
        A context manager.  Upon entering the manager, return the
        managed subprocess.  Upon exiting the manager, terminate the
        process and wait for it.

    """
    try:
        yield proc
    finally:
        proc.terminate()
        proc.wait()


class CannotSpawnError(RuntimeError):
    """Cannot spawn the SSH agent."""


def spawn_named_agent(  # noqa: C901
    executable: str | None,
    spawn_func: SSHAgentSpawnFunc | SSHAgentInterfaceFunc,
    agent_type: data.KnownSSHAgent,
    agent_name: str,
) -> Iterator[data.SpawnedSSHAgentInfo]:  # pragma: no cover [external]
    """Spawn the named SSH agent and check that it is operational.

    Using the correct agent-specific spawn function from the
    [`spawn_handlers`][] registry, spawn the named SSH agent (according
    to its declared type), then set up the communication channel and
    yield an SSH agent client connected to this agent.  After resuming,
    tear down the communication channel and terminate the SSH agent.

    The SSH agent's instructions for setting up the communication
    channel are parsed with [`callables.parse_sh_export_line`][].  See
    the caveats there.

    Args:
        executable:
            The full path of the executable to spawn.  If not given, we
            attempt to spawn the agent under its conventional executable
            name.
        spawn_func:
            The agent-specific spawn function.
        agent_type:
            The agent type.
        agent_name:
            The agent's display name.

    Yields:
        A 3-tuple containing the agent type, an SSH agent client
        connected to this agent, and a boolean indicating whether this
        agent was actually spawned in an isolated manner.

        Only one tuple will ever be yielded.  After resuming, the
        connected client will be torn down, as will the agent if it was
        isolated.

    Raises:
        CannotSpawnError:
            We failed to spawn the agent or otherwise set up the
            environment/communication channel/etc.

    """
    # pytest's fixture system does not seem to guarantee that
    # environment variables are set up correctly if nested and
    # parametrized fixtures are used: it is possible that "outer"
    # parametrized fixtures are torn down only after other "outer"
    # fixtures of the same parameter set have run.  So our fixtures set
    # SSH_AUTH_SOCK explicitly to the value saved at interpreter
    # startup.
    #
    # Here, we verify at most major steps that SSH_AUTH_SOCK didn't
    # change under our nose.
    assert os.environ.get("SSH_AUTH_SOCK") == startup_ssh_auth_sock, (
        f"SSH_AUTH_SOCK mismatch when checking for spawnable {agent_name}"
    )
    exit_stack = contextlib.ExitStack()
    agent_env = os.environ.copy()
    ssh_auth_sock = agent_env.pop("SSH_AUTH_SOCK", None)
    proc_or_socket = spawn_func(executable=executable, env=agent_env)
    with exit_stack:
        if agent_type == data.KnownSSHAgent.StubbedSSHAgent:
            ssh_auth_sock = None
        elif spawn_func is spawn_noop:
            ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK")
        elif proc_or_socket is None:  # pragma: no cover [external]
            err_msg = f"Cannot spawn or interface with usable {agent_name}"
            raise CannotSpawnError(err_msg)
        elif isinstance(proc_or_socket, subprocess.Popen):
            proc = proc_or_socket
            exit_stack.enter_context(terminate_on_exit(proc))
            assert os.environ.get("SSH_AUTH_SOCK") == startup_ssh_auth_sock, (
                f"SSH_AUTH_SOCK mismatch after spawning {agent_name}"
            )
            assert proc.stdout is not None
            ssh_auth_sock_line = proc.stdout.readline()
            try:
                ssh_auth_sock = callables.parse_sh_export_line(
                    ssh_auth_sock_line, env_name="SSH_AUTH_SOCK"
                )
            except ValueError:  # pragma: no cover [external]
                err_msg = f"Cannot parse agent output: {ssh_auth_sock_line!r}"
                raise CannotSpawnError(err_msg) from None
            pid_line = proc.stdout.readline()
            if (
                "pid" not in pid_line.lower()
                and "_pid" not in pid_line.lower()
            ):  # pragma: no cover [external]
                err_msg = f"Cannot parse agent output: {pid_line!r}"
                raise CannotSpawnError(err_msg)
        monkeypatch = exit_stack.enter_context(pytest.MonkeyPatch.context())
        if agent_type == data.KnownSSHAgent.StubbedSSHAgent:
            assert ssh_auth_sock is None
            monkeypatch.setenv(
                "SSH_AUTH_SOCK",
                machinery.StubbedSSHAgentSocketWithAddress.ADDRESS,
            )
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient,
                "SOCKET_PROVIDERS",
                ["stub_agent_with_address_and_deterministic_dsa"]
                if "stub_agent_with_address_and_deterministic_dsa"
                in agent_name
                else ["stub_agent_with_address"],
            )
            client = exit_stack.enter_context(
                ssh_agent.SSHAgentClient.ensure_agent_subcontext(
                    machinery.StubbedSSHAgentSocketWithAddressAndDeterministicDSA()
                    if "stub_agent_with_address_and_deterministic_dsa"
                    in agent_name
                    else machinery.StubbedSSHAgentSocketWithAddress()
                )
            )
        elif (
            not isinstance(proc_or_socket, subprocess.Popen)
            and proc_or_socket is not None
        ):
            socket: _types.SSHAgentSocket = proc_or_socket
            client = exit_stack.enter_context(
                ssh_agent.SSHAgentClient.ensure_agent_subcontext(conn=socket)
            )
        else:
            if ssh_auth_sock:
                monkeypatch.setenv("SSH_AUTH_SOCK", ssh_auth_sock)
            client = exit_stack.enter_context(
                ssh_agent.SSHAgentClient.ensure_agent_subcontext()
            )
        # We sanity-test the connected SSH agent if it is not one of our
        # test agents, because allowing the user to run the test suite
        # with a clearly faulty agent would likely and unfairly
        # misattribute the agent's protocol violations to our test
        # suite.  On the flip side, for our own test agents, the
        # correctness tests are part of the test suite, so we don't want
        # the *setup* code here to already decide that the agent is
        # unsuitable. Therefore, do a sanity check if and only if the
        # agent is not one of our test agents, and if the check fails,
        # skip this agent.
        if (
            agent_type != data.KnownSSHAgent.StubbedSSHAgent
        ):  # pragma: no cover [external]
            try:
                client.list_keys()  # sanity test
            except (
                EOFError,
                OSError,
                ssh_agent.SSHAgentFailedError,
            ) as exc:  # pragma: no cover [failsafe]
                msg = f'agent failed the "list keys" sanity test: {exc!r}'
                raise CannotSpawnError(msg) from exc
        yield data.SpawnedSSHAgentInfo(
            agent_type,
            client,
            spawn_func is not spawn_noop
            if isinstance(proc_or_socket, subprocess.Popen)
            else False,
        )
    assert os.environ.get("SSH_AUTH_SOCK", None) == startup_ssh_auth_sock, (
        f"SSH_AUTH_SOCK mismatch after tearing down {agent_name}"
    )


@pytest.fixture
def running_ssh_agent(  # pragma: no cover [external]
) -> Iterator[data.RunningSSHAgentInfo]:
    """Ensure a running SSH agent, if possible, as a pytest fixture.

    Check for a running SSH agent, or spawn a new one if possible.  We
    know how to spawn OpenSSH's agent and PuTTY's Pageant.  If spawned
    this way, the agent does not persist beyond the test.

    This fixture can neither guarantee a particular running agent, nor
    can it guarantee a particular set of loaded keys.

    Yields:
        A 2-tuple `(ssh_auth_sock, agent_type)`, where `ssh_auth_sock`
        is the value of the `SSH_AUTH_SOCK` environment variable, to be
        used to connect to the running agent, and `agent_type` is the
        agent type.

    Raises:
        pytest.skip.Exception:
            If no agent is running or can be spawned, skip this test.

    """

    def prepare_environment(
        agent_type: data.KnownSSHAgent,
    ) -> Iterator[data.RunningSSHAgentInfo]:
        with pytest.MonkeyPatch.context() as monkeypatch:
            if agent_type == data.KnownSSHAgent.StubbedSSHAgent:
                monkeypatch.setattr(
                    ssh_agent.SSHAgentClient,
                    "SOCKET_PROVIDERS",
                    ["stub_agent_with_address"],
                )
                monkeypatch.setenv(
                    "SSH_AUTH_SOCK",
                    machinery.StubbedSSHAgentSocketWithAddress.ADDRESS,
                )
                yield data.RunningSSHAgentInfo(
                    machinery.StubbedSSHAgentSocketWithAddressAndDeterministicDSA,
                    data.KnownSSHAgent.StubbedSSHAgent,
                )
            else:
                yield data.RunningSSHAgentInfo(
                    os.environ["SSH_AUTH_SOCK"],
                    agent_type,
                )

    with pytest.MonkeyPatch.context() as monkeypatch:
        # pytest's fixture system does not seem to guarantee that
        # environment variables are set up correctly if nested and
        # parametrized fixtures are used: it is possible that "outer"
        # parametrized fixtures are torn down only after other "outer"
        # fixtures of the same parameter set have run.  So set
        # SSH_AUTH_SOCK explicitly to the value saved at interpreter
        # startup.
        if startup_ssh_auth_sock:
            monkeypatch.setenv("SSH_AUTH_SOCK", startup_ssh_auth_sock)
        else:
            monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
        for handler in spawn_handlers.values():
            if not is_agent_permitted(handler.agent_type):
                continue
            try:
                for _agent_info in spawn_named_agent(
                    executable=handler.executable,
                    spawn_func=handler.spawn_func,
                    agent_type=handler.agent_type,
                    agent_name=handler.agent_name or handler.key,
                ):
                    yield from prepare_environment(handler.agent_type)
            except (KeyError, OSError, CannotSpawnError):
                continue
            return
        pytest.skip("No SSH agent running or spawnable")


@pytest.fixture(params=spawn_handlers_params)
def spawn_ssh_agent(
    request: pytest.FixtureRequest,
) -> Iterator[data.SpawnedSSHAgentInfo]:  # pragma: no cover [external]
    """Spawn an isolated SSH agent, if possible, as a pytest fixture.

    Spawn a new SSH agent isolated from other SSH use by other
    processes, if possible.  We know how to spawn OpenSSH's agent (on
    UNIX) and PuTTY's Pageant (on UNIX), the stubbed agents, and the
    "(system)" fallback agent.

    Yields:
        A [named tuple][collections.namedtuple] containing information
        about the spawned agent, e.g. the software product, a client
        connected to the agent, and whether the agent is isolated from
        other clients.

    Raises:
        pytest.skip.Exception:
            If the agent cannot be spawned, skip this test.

    """

    with pytest.MonkeyPatch.context() as monkeypatch:
        # pytest's fixture system does not seem to guarantee that
        # environment variables are set up correctly if nested and
        # parametrized fixtures are used: it is possible that "outer"
        # parametrized fixtures are torn down only after other "outer"
        # fixtures of the same parameter set have run.  So set
        # SSH_AUTH_SOCK explicitly to the value saved at interpreter
        # startup.
        if startup_ssh_auth_sock:  # pragma: no cover [external]
            monkeypatch.setenv("SSH_AUTH_SOCK", startup_ssh_auth_sock)
        else:  # pragma: no cover [external]
            monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
        try:
            yield from spawn_named_agent(
                executable=request.param.executable,
                spawn_func=request.param.spawn_func,
                agent_type=request.param.agent_type,
                agent_name=request.param.agent_name or request.param.key,
            )
        except KeyError as exc:
            pytest.skip(
                f"The environment variable {exc.args[0]!r} was not found"
                if exc.__class__ is KeyError
                else exc.args[0]
            )
        except (OSError, CannotSpawnError) as exc:
            name = request.param.agent_name or request.param.key
            pytest.skip(f"Cannot spawn {name}: {exc}")
        return


def _prepare_payload(
    payload: bytes | bytearray,
    *,
    isolated: bool = True,
    time_to_live: int = 30,
) -> tuple[_types.SSH_AGENTC, bytes]:
    """Return a full payload for an "add key" request to the agent.

    For isolated agents, return a standard
    [`_types.SSH_AGENTC.ADD_IDENTITY`][] request payload.  For
    non-isolated agents, return a
    [`_types.SSH_AGENTC.ADD_ID_CONSTRAINED`][] request payload with the
    specified time-to-live value.

    Args:
        payload:
            The private key to upload, already formatted suitably.
        isolated:
            `True` if the agent is isolated, `False` otherwise.
        time_to_live:
            The amount of seconds to hold the key in the agent, if not
            isolated.

    """
    return_code = (
        _types.SSH_AGENTC.ADD_IDENTITY
        if isolated
        else _types.SSH_AGENTC.ADD_ID_CONSTRAINED
    )
    lifetime_constraint = (
        b""
        if isolated
        else b"\x01" + ssh_agent.SSHAgentClient.uint32(time_to_live)
    )
    return (return_code, bytes(payload) + lifetime_constraint)


def _load_key_optimistically(
    spawned_agent_info: data.SpawnedSSHAgentInfo,
    key_struct: data.SSHTestKey,
) -> bool:
    """Load a test key optimistically into the spawned agent.

    Load the key with a time-to-live constraint (if isolated) or not, as
    appropriate.  If that fails because this agent does not support key
    constraints, retry it without constraints.

    Args:
        spawned_agent_info: Info on the spawned agent.
        key_struct: The struct for the SSH test key to upload.

    Returns:
        `True` if the key was successfully uploaded, `False` otherwise.
        Retrying an upload because key constraints are not supported
        still counts as successfully uploaded.

    """
    agent_type, client, isolated = spawned_agent_info
    private_key_data = key_struct.private_key_blob
    request_code, payload = _prepare_payload(
        private_key_data, isolated=isolated, time_to_live=30
    )
    try:
        try:
            client.request(
                request_code,
                payload,
                response_code=_types.SSH_AGENT.SUCCESS,
            )
        except ssh_agent.SSHAgentFailedError:  # pragma: no cover [external]
            # Pageant can fail to accept a key for two separate reasons:
            #
            # - Pageant refuses to accept a key it already holds in
            #   memory.  Verify this by listing keys.
            # - Pageant does not support key constraints (see
            #   references below).
            #
            # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/pageant-timeout.html
            # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/pageant-key-confirm.html
            current_loaded_keys = frozenset({
                pair.key for pair in client.list_keys()
            })
            if (
                agent_type
                in {data.KnownSSHAgent.UNIXPageant, data.KnownSSHAgent.Pageant}
                and key_struct.public_key_data in current_loaded_keys
            ):
                pass
            elif (
                agent_type
                in {data.KnownSSHAgent.UNIXPageant, data.KnownSSHAgent.Pageant}
                and not isolated
            ):
                request_code, payload = _prepare_payload(
                    private_key_data, isolated=True
                )
                client.request(
                    request_code,
                    payload,
                    response_code=_types.SSH_AGENT.SUCCESS,
                )
            else:
                raise
    except (
        EOFError,
        OSError,
        ssh_agent.SSHAgentFailedError,
    ):  # pragma: no cover [external]
        return False
    else:  # pragma: no cover [external]
        return True


@pytest.fixture
def ssh_agent_client_with_test_keys_loaded(
    spawn_ssh_agent: data.SpawnedSSHAgentInfo,
) -> Iterator[ssh_agent.SSHAgentClient]:
    """Provide an SSH agent with loaded test keys, as a pytest fixture.

    Use the `spawn_ssh_agent` fixture to acquire a usable SSH agent,
    upload the known test keys into the agent, and return a connected
    client.

    The agent may reject several of the test keys due to unsupported or
    obsolete key types.  Rejected keys will be silently ignored, unless
    all keys are rejected; then the test will be skipped.  You must not
    automatically assume any particular key is present in the agent.

    Yields:
        A [named tuple][collections.namedtuple] containing
        information about the spawned agent, e.g. the software
        product, a client connected to the agent, and whether the
        agent is isolated from other clients.

    Raises:
        OSError:
            There was a communication or a socket setup error with the
            agent.
        pytest.skip.Exception:
            If the agent is unusable or if it rejected all test keys,
            skip this test.

    Warning:
        It is this fixture's responsibility to clean up the SSH agent
        client after the test.  Closing the client's socket connection
        beforehand (e.g. by using the client as a context manager) may
        lead to exceptions being thrown upon fixture teardown.

    """
    agent_type, client, isolated = spawn_ssh_agent
    successfully_loaded_keys: set[str] = set()

    # This fixture relies on `spawn_ssh_agent`, which in turn uses
    # `spawn_named_agent` to, well, spawn agents.  `spawn_named_agent`
    # runs sanity tests on the agents it spawns, via
    # `SSHAgentClient.list_keys`.  There is thus little point in
    # repeating the very same sanity test here, on an agent that was
    # already sanity-tested.
    #
    # (But see below, too.)

    try:
        successfully_loaded_keys = {
            key_type
            for key_type, key_struct in data.ALL_KEYS.items()
            if _load_key_optimistically(spawn_ssh_agent, key_struct)
        }
        if (
            agent_type != data.KnownSSHAgent.StubbedSSHAgent
            and not successfully_loaded_keys
        ):  # pragma: no cover [external]
            pytest.skip("Failed to load any test keys at all into the agent.")
        # Sanity-test the agent.  It makes sense to do this here (unlike
        # at the top of this fixture), because we ignore errors when
        # adding keys above, but badly behaved SSH agents such as the
        # Annoying OS port of OpenSSH 10.0p1 (Dec 2025) may have already
        # closed the connection.
        try:
            client.list_keys()
        except (
            EOFError,
            OSError,
            ssh_agent.SSHAgentFailedError,
        ):  # pragma: no cover [external]
            pytest.skip(
                "The agent became unusable during test fixture setup.  "
                "(Sanity check failed.)"
            )
        yield client
    finally:
        if not isolated:  # pragma: no cover [external]
            for key_type in successfully_loaded_keys:
                key_struct = data.ALL_KEYS[key_type]
                # The public key blob is the base64-encoded part in
                # the "public key line".
                public_key = base64.standard_b64decode(
                    key_struct.public_key.split(None, 2)[1]
                )
                request_code = _types.SSH_AGENTC.REMOVE_IDENTITY
                client.request(
                    request_code,
                    public_key,
                    response_code=frozenset({
                        _types.SSH_AGENT.SUCCESS,
                        _types.SSH_AGENT.FAILURE,
                    }),
                )
