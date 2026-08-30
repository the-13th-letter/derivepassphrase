# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import base64
import contextlib
import ctypes
import os
import shutil
import socket
import subprocess
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

import packaging.version
import pytest
from typing_extensions import NamedTuple

from derivepassphrase import _types, ssh_agent
from derivepassphrase.ssh_agent import socketprovider
from tests import data, machinery
from tests.data import callables
from tests.machinery import hypothesis as hypothesis_machinery
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence

    import derivepassphrase_sshagentsocketprovider as d_sasp

startup_ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK", None)


def pytest_configure(config: pytest.Config) -> None:
    """Configure `pytest`: add custom markers."""
    config.addinivalue_line(
        "markers", ("heavy_duty: mark test as a slow, heavy-duty test")
    )
    config.addinivalue_line(
        "markers",
        (
            "correctness_focused: "
            "mark test as a potentially slow, correctness-focused test"
        ),
    )
    config.addinivalue_line(
        "markers",
        (
            "external_agent: "
            "mark the agent (fixture output) as external to the test suite"
        ),
    )
    config.addinivalue_line(
        "markers",
        (
            "non_reentrant_agent: "
            "mark the agent (fixture output) as non-reentrant"
        ),
    )
    hypothesis_machinery._hypothesis_settings_setup()


# https://docs.pytest.org/en/stable/explanation/fixtures.html#a-note-about-fixture-cleanup
# https://github.com/pytest-dev/pytest/issues/5243#issuecomment-491522595
@pytest.fixture(scope="session", autouse=False)
def term_handler() -> Generator[
    None, None, None
]:  # pragma: no cover [external]
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
    """Skip the test if Python does not support `AF_UNIX`.

    Implemented as a fixture instead of a mark because another "autouse"
    session fixture may want to force/simulate non-support of
    [`socket.AF_UNIX`][].

    """
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("No Python or system support for UNIX domain sockets.")


@pytest.fixture(scope="session")
def skip_if_no_ctypes_windll_support() -> None:  # pragma: no cover [external]
    """Skip the test if Python does not support WinDLL in `ctypes`.

    Implemented as a fixture instead of a mark because another "autouse"
    session fixture may want to force/simulate non-support of
    [`ctypes.WinDLL`][].

    """
    if not hasattr(ctypes, "WinDLL"):
        pytest.skip(
            "No Python or system support for interfacing Windows DLLs."
        )


@pytest.fixture
def use_stub_agent() -> Generator[None, None, None]:
    """Enforce use of the stubbed SSH agent."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            ssh_agent.SSHAgentClient,
            "SOCKET_PROVIDERS",
            (_types.BuiltinSSHAgentSocketProvider.STUB_AGENT,),
        )
        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
        yield


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
    ) -> tuple[d_sasp.SSHAgentSocket, str] | None:
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
            A 2-tuple, if possible, containing an abstract socket
            connected to the specified SSH agent and the associated
            address; otherwise, `None`.

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
) -> tuple[d_sasp.SSHAgentSocket, str] | None:  # pragma: no cover [external]
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
        socket = socketprovider.SocketProvider.windows_named_pipe_for_pageant()
    except socketprovider.WindowsNamedPipesNotAvailableError:
        return None
    else:
        return (socket, socket.named_pipe_name())


def interface_openssh_agent_on_the_annoying_os(
    executable: str | None,
    env: dict[str, Any],
) -> tuple[d_sasp.SSHAgentSocket, str] | None:  # pragma: no cover [external]
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
        socket = socketprovider.SocketProvider.windows_named_pipe_for_openssh()
    except socketprovider.WindowsNamedPipesNotAvailableError:
        return None
    else:
        return (socket, socket.named_pipe_name())


class SpawnHandler(NamedTuple):
    """A handler for a spawned or interfaced SSH agent.

    (The choice of terminology "spawn" instead of the more accurate
    "spawn or interface" is due to historical reasons.)

    Attributes:
        instance:
            The SSH agent instance type under which this handler is
            registered.

            This is a full enum, not just a string.  In particular, the
            enum can be queried for the type of agent represented by
            this entry.
        executable:
            The (optional) full path to the executable.
        spawn_func:
            The spawn function.
        agent_name:
            The (optional) display name for this handler.

    """

    instance: data.KnownSSHAgentInstance
    executable: str | None
    spawn_func: SSHAgentSpawnFunc | SSHAgentInterfaceFunc
    agent_name: str | None


spawn_handlers: dict[str, SpawnHandler] = {
    data.KnownSSHAgentInstance.unix_pageant: SpawnHandler(
        data.KnownSSHAgentInstance.unix_pageant,
        None,
        spawn_pageant_on_posix,
        "Pageant (UNIX)",
    ),
    data.KnownSSHAgentInstance.openssh: SpawnHandler(
        data.KnownSSHAgentInstance.openssh,
        None,
        spawn_openssh_agent_on_posix,
        "ssh-agent (OpenSSH)",
    ),
    data.KnownSSHAgentInstance.pageant: SpawnHandler(
        data.KnownSSHAgentInstance.pageant,
        None,
        interface_pageant_on_the_annoying_os,
        "Pageant",
    ),
    data.KnownSSHAgentInstance.openssh_on_windows: SpawnHandler(
        data.KnownSSHAgentInstance.openssh_on_windows,
        None,
        interface_openssh_agent_on_the_annoying_os,
        "ssh-agent (OpenSSH on Windows)",
    ),
    data.KnownSSHAgentInstance.stub_agent_with_address: SpawnHandler(
        data.KnownSSHAgentInstance.stub_agent_with_address,
        None,
        spawn_noop,
        "stub_agent_with_address (derivepassphrase test suite)",
    ),
    data.KnownSSHAgentInstance.stub_agent_with_address_and_deterministic_dsa: SpawnHandler(
        data.KnownSSHAgentInstance.stub_agent_with_address_and_deterministic_dsa,
        None,
        spawn_noop,
        "stub_agent_with_address_and_deterministic_dsa "
        "(derivepassphrase test suite)",
    ),
    data.KnownSSHAgentInstance.system_agent: SpawnHandler(
        data.KnownSSHAgentInstance.system_agent,
        None,
        spawn_noop,
        None,
    ),
}
"""
The standard registry of agent spawning/interfacing functions.

(The choice of terminology "spawn" instead of the more accurate "spawn
or interface" is due to historical reasons.)
"""


def external_agent_restriction(
    agent_type: data.KnownSSHAgentType,
    env_var: str,
    *,
    default: bool = True,
) -> bool:  # pragma: no cover [external]
    """Classify an SSH agent according to some environment variable.

    Look up the given SSH agent type in a certain environment variable,
    and report on whether the agent type is listed in that variable.
    This can be used to check if the agent is e.g. in a list of
    permitted agents, or if it is in the list of agents requiring
    special workarounds.  Invalid agent type names are silently ignored.

    If the environment variable is empty, return a default value.

    By design, the stubbed agents have a fixed classification (the
    default value), unaffected by the environment variable.

    Args:
        agent_type:
            The agent type to classify.
        env_var:
            The environment variable in which to look up the agent type
            name.
        default:
            The value to return if the environment variable is unset, or
            if a stub agent is to be classified.

    Returns:
        If the agent type is not a stub agent, and the environment
        variable is non-empty, then `True` if the agent type is
        mentioned in the environment variable, and `False` otherwise;
        the default value otherwise.

    See also:
        [`is_agent_permitted`][] and [`is_agent_non_reentrant`][], which
        make use of this function internally.

    """
    if agent_type == data.KnownSSHAgentType.StubbedSSHAgent:
        return default
    if not os.environ.get(env_var):
        return default
    marked_agents = {
        data.KnownSSHAgentType(x)
        for x in os.environ[env_var].split(",")
        if x in data.KnownSSHAgentType.__members__
    }
    return agent_type in marked_agents


def is_agent_permitted(
    agent_type: data.KnownSSHAgentType,
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
    return external_agent_restriction(
        agent_type, "PERMITTED_SSH_AGENTS", default=True
    )


def is_agent_non_reentrant(
    agent_type: data.KnownSSHAgentType,
) -> bool:  # pragma: no cover [external]
    """Is the given SSH agent assumed to be non-reentrant?

    If the environment variable `NON_REENTRANT_SSH_AGENTS` is given, it
    names a comma-separated list of known SSH agent names that are
    assumed to be non-reentrant, i.e., where the SSH agent cannot
    tolerate multiple clients connecting to it at the same time, and
    thus no client for the same agent may be constructed while another
    one is already connected.  Invalid names are silently ignored.  If
    not given, or empty, then all agents are considered reentrant, i.e.,
    all agents are not considered non-reentrant.

    (To consider all agents non-reentrant, specify a single comma as the
    list.  But see below.)

    The stubbed agents cannot be influenced in this manner, as the test
    suite depends on their reentrancy.

    """
    return external_agent_restriction(
        agent_type, "NON_REENTRANT_SSH_AGENTS", default=False
    )


spawn_handlers_params: list[Sequence] = []
"""
The standard registry of agent spawning functions, annotated as
a `pytest` parameter set.  (In particular, this includes the conditional
skip marks.)  Used by some test fixtures.

(The choice of terminology "spawn" instead of the more accurate "spawn
or interface" is due to historical reasons.)
"""
for instance, handler in spawn_handlers.items():
    marks = [
        pytest.mark.skipif(
            not is_agent_permitted(handler.instance.agent_type),
            reason="SSH agent excluded via PERMITTED_AGENTS "
            "environment variable.",
        ),
    ]
    agent_type = handler.instance.agent_type
    # Distinguish spawned/interfaced agents ("external agents") from the
    # stub agents ("internal agents").  While this could be inferred from
    # the other marks, it is sensible to have a dedicated mark for this.
    # Tests that unnecessarily use external agents without testing anything
    # that is specific to external agents can be found more easily using
    # this mark, and converted to using internal agents only, with speed and
    # flakiness-resistance benefits.
    if agent_type != data.KnownSSHAgentType.StubbedSSHAgent:
        marks.append(pytest.mark.external_agent)
    # Allow agents to be marked as non-reentrant.  Workaround for an
    # issue with GnuPG 2.4.8 on The Annoying OS when `gpg-agent`
    # masquerades as OpenSSH's `ssh-agent`.
    if is_agent_non_reentrant(agent_type):  # pragma: no cover [external]
        marks.append(pytest.mark.non_reentrant_agent)
    # Mark non-isolated agents as, well, using non-isolated agents.
    # Assume by default that an agent is potentially non-isolated unless
    # we can be absolutely sure it is isolated, by design.  (The "stub"
    # agents fall into the latter category.)
    if agent_type != data.KnownSSHAgentType.StubbedSSHAgent:
        marks.append(pytest_machinery.non_isolated_agent_use)
    # Some agents require UNIX domain socket support.
    if instance in {
        data.KnownSSHAgentInstance.unix_pageant,
        data.KnownSSHAgentInstance.openssh,
    }:
        marks.append(
            pytest.mark.skipif(
                not hasattr(socket, "AF_UNIX"),
                reason="No Python or system support for UNIX domain sockets.",
            )
        )
    # Others require Windows named pipe support.
    if instance in {
        data.KnownSSHAgentInstance.pageant,
        data.KnownSSHAgentInstance.openssh_on_windows,
    }:
        marks.append(
            pytest.mark.skipif(
                not hasattr(ctypes, "WinDLL"),
                reason="No Python or system support for Windows named pipes.",
            )
        )
    spawn_handlers_params.append(
        pytest.param(handler, id=instance, marks=marks)
    )


Popen = TypeVar("Popen", bound=subprocess.Popen)


# As of v0.6, all SSH agents we interact with on The Annoying OS are
# interfaced, not spawned.  Therefore, this context manager is unused on
# The Annoying OS.
@contextlib.contextmanager
def terminate_on_exit(
    proc: Popen,
) -> Generator[Popen, None, None]:  # pragma: unless posix no cover [unused]
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
    agent_type: data.KnownSSHAgentType,
    agent_name: str,
) -> Generator[
    data.SpawnedSSHAgentInfo, None, None
]:  # pragma: no cover [external]
    """Spawn the named SSH agent and check that it is operational.

    Using the correct agent-specific spawn function from the
    [`spawn_handlers`][] registry, spawn the named SSH agent (according
    to its declared type), then set up the communication channel and
    yield an SSH agent client connected to this agent.  After resuming,
    tear down the communication channel and terminate the SSH agent.

    The SSH agent's instructions for setting up the communication
    channel are parsed with [`callables.parse_sh_export_line`][].  See
    the caveats there.

    (The choice of terminology "spawned" instead of the more accurate
    "spawned or interfaced" is due to historical reasons.)

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
    proc_or_socket_data = spawn_func(executable=executable, env=agent_env)
    with exit_stack:
        if agent_type == data.KnownSSHAgentType.StubbedSSHAgent:
            ssh_auth_sock = None
        elif spawn_func is spawn_noop:
            ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK")
        elif proc_or_socket_data is None:  # pragma: no cover [external]
            err_msg = f"Cannot spawn or interface with usable {agent_name}"
            raise CannotSpawnError(err_msg)
        elif isinstance(proc_or_socket_data, subprocess.Popen):
            proc = proc_or_socket_data
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
        else:
            ssh_auth_sock = proc_or_socket_data[1]
        monkeypatch = exit_stack.enter_context(pytest.MonkeyPatch.context())
        if agent_type == data.KnownSSHAgentType.StubbedSSHAgent:
            assert ssh_auth_sock is None
            monkeypatch.setenv(
                "SSH_AUTH_SOCK",
                machinery.StubbedSSHAgentSocketWithAddress.ADDRESS,
            )
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient,
                "SOCKET_PROVIDERS",
                [
                    data.KnownSSHAgentInstance.stub_agent_with_address_and_deterministic_dsa
                ]
                if "stub_agent_with_address_and_deterministic_dsa"
                in agent_name
                else [data.KnownSSHAgentInstance.stub_agent_with_address],
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
            not isinstance(proc_or_socket_data, subprocess.Popen)
            and proc_or_socket_data is not None
        ):
            socket: d_sasp.SSHAgentSocket
            socket, ssh_auth_sock = proc_or_socket_data
            monkeypatch.setenv("SSH_AUTH_SOCK", ssh_auth_sock)
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
            agent_type != data.KnownSSHAgentType.StubbedSSHAgent
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
            if isinstance(proc_or_socket_data, subprocess.Popen)
            else False,
        )
    assert os.environ.get("SSH_AUTH_SOCK", None) == startup_ssh_auth_sock, (
        f"SSH_AUTH_SOCK mismatch after tearing down {agent_name}"
    )


# Hack: We cannot associate markers with fixtures (the pytest devs say
# there are many unresolved questions when it comes to fixture and
# marker overriding in such a case), so we fake this by trivially
# parametrizing the fixture.  (The parametrizations *can* contain the
# necessary marks.)
@pytest.fixture(
    params=[
        pytest.param(
            "non_isolated_agent_use",
            marks=pytest_machinery.non_isolated_agent_use,
        )
    ]
)
def running_ssh_agent(  # pragma: no cover [external]
    request: pytest.FixtureRequest,
) -> Generator[data.RunningSSHAgentInfo, None, None]:
    """Ensure a running SSH agent, if possible, as a pytest fixture.

    Check for a running SSH agent, or spawn/interface a new one if
    possible.  We know how to spawn OpenSSH's agent and PuTTY's Pageant
    on UNIX, or interface them on The Annoying OS.  If spawned this way,
    the agent does not persist beyond the test.

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
    del request

    def prepare_environment(
        agent_type: data.KnownSSHAgentType,
    ) -> Generator[data.RunningSSHAgentInfo, None, None]:
        with pytest.MonkeyPatch.context() as monkeypatch:
            if agent_type == data.KnownSSHAgentType.StubbedSSHAgent:
                monkeypatch.setattr(
                    ssh_agent.SSHAgentClient,
                    "SOCKET_PROVIDERS",
                    [
                        _types.BuiltinSSHAgentSocketProvider.STUB_AGENT_WITH_ADDRESS
                    ],
                )
                monkeypatch.setenv(
                    "SSH_AUTH_SOCK",
                    machinery.StubbedSSHAgentSocketWithAddress.ADDRESS,
                )
                yield data.RunningSSHAgentInfo(
                    machinery.StubbedSSHAgentSocketWithAddressAndDeterministicDSA,
                    data.KnownSSHAgentType.StubbedSSHAgent,
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
            if not is_agent_permitted(handler.instance.agent_type):
                continue
            try:
                for _agent_info in spawn_named_agent(
                    executable=handler.executable,
                    spawn_func=handler.spawn_func,
                    agent_type=handler.instance.agent_type,
                    agent_name=handler.agent_name or handler.instance,
                ):
                    yield from prepare_environment(handler.instance.agent_type)
            except (KeyError, OSError, CannotSpawnError):
                continue
            return
        pytest.skip("No SSH agent running or spawnable")


@pytest.fixture(params=spawn_handlers_params)
def spawn_ssh_agent(
    request: pytest.FixtureRequest,
) -> Generator[
    data.SpawnedSSHAgentInfo, None, None
]:  # pragma: no cover [external]
    """Spawn or interface an SSH agent, as a pytest fixture.

    Spawn a new SSH agent (isolated from other SSH use by other
    processes, on a best-effort basis), or interface a running
    (non-isolated) SSH agent.  We know how to spawn OpenSSH's agent (on
    UNIX) and PuTTY's Pageant (on UNIX) and the stubbed agents, and how
    to interface PuTTY's Pageant (on The Annoying OS), OpenSSH's agent
    (on The Annoying OS) and the "system" agent (on every OS).

    (The choice of terminology "spawned" instead of the more accurate
    "spawned or interfaced" is due to historical reasons.)

    Yields:
        A [named tuple][collections.namedtuple] containing information
        about the spawned agent, e.g. the software product, a client
        connected to the agent, and whether the agent is isolated from
        other clients.

    Raises:
        pytest.skip.Exception:
            If the agent cannot be spawned or interfaced, skip this
            test.

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
                agent_type=request.param.instance.agent_type,
                agent_name=request.param.agent_name or request.param.instance,
            )
        except KeyError as exc:
            pytest.skip(
                f"The environment variable {exc.args[0]!r} was not found"
                if exc.__class__ is KeyError
                else exc.args[0]
            )
        except (OSError, CannotSpawnError) as exc:
            name = request.param.agent_name or request.param.instance
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
                in {
                    data.KnownSSHAgentType.UNIXPageant,
                    data.KnownSSHAgentType.Pageant,
                }
                and key_struct.public_key_data in current_loaded_keys
            ):
                pass
            elif (
                agent_type
                in {
                    data.KnownSSHAgentType.UNIXPageant,
                    data.KnownSSHAgentType.Pageant,
                }
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
) -> Generator[ssh_agent.SSHAgentClient, None, None]:
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
            agent_type != data.KnownSSHAgentType.StubbedSSHAgent
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
        request_code = _types.SSH_AGENTC.REMOVE_IDENTITY
        # For isolated agents, we have full control over the loaded key
        # set, and thus expect to successfully unload every key. For
        # non-isolated agents, the user or another process may load or
        # unload keys in the meantime, so we cannot assume that the
        # operation will succeed.
        response_code = (
            frozenset({_types.SSH_AGENT.SUCCESS})
            if isolated
            else frozenset({
                _types.SSH_AGENT.SUCCESS,
                _types.SSH_AGENT.FAILURE,
            })
        )
        for key_type in successfully_loaded_keys:
            key_struct = data.ALL_KEYS[key_type]
            # The public key blob is the base64-encoded part in
            # the "public key line".
            public_key = base64.standard_b64decode(
                key_struct.public_key.split(None, 2)[1]
            )
            # Though unnecessary for isolated agents, unloading the key
            # is vital functionality for non-isolated agents.  We thus
            # always unload keys, and use the "isolated agent" case as
            # a smoke test for the more brittle "non-isolated agent"
            # case.
            client.request(
                request_code,
                ssh_agent.SSHAgentClient.string(public_key),
                response_code=response_code,
            )
