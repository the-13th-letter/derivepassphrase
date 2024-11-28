# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import base64
import contextlib
import operator
import os
import shutil
import socket
import subprocess
import sys
import textwrap
from typing import TYPE_CHECKING, TypeVar

import hypothesis
import packaging.version
import pytest

import tests
from derivepassphrase import _types, ssh_agent

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Literal

startup_ssh_auth_sock = os.environ.get('SSH_AUTH_SOCK', None)

# https://hypothesis.readthedocs.io/en/latest/settings.html#settings-profiles
hypothesis.settings.register_profile('ci', max_examples=1000)
hypothesis.settings.register_profile('dev', max_examples=10)
hypothesis.settings.register_profile(
    'debug', max_examples=10, verbosity=hypothesis.Verbosity.verbose
)


# https://docs.pytest.org/en/stable/explanation/fixtures.html#a-note-about-fixture-cleanup
# https://github.com/pytest-dev/pytest/issues/5243#issuecomment-491522595
@pytest.fixture(scope='session', autouse=True)
def term_handler() -> Iterator[None]:  # pragma: no cover
    try:
        import signal  # noqa: PLC0415

        sigint_handler = signal.getsignal(signal.SIGINT)
    except (ImportError, OSError):
        return
    else:
        orig_term = signal.signal(signal.SIGTERM, sigint_handler)
        yield
        signal.signal(signal.SIGTERM, orig_term)


@pytest.fixture(scope='session')
def skip_if_no_af_unix_support() -> None:  # pragma: no cover
    """Skip the test if Python does not support AF_UNIX.

    Implemented as a fixture instead of a mark because it has
    consequences for other fixtures, and because another "autouse"
    session fixture may want to force/simulate non-support of
    [`socket.AF_UNIX`][].

    """
    if not hasattr(socket, 'AF_UNIX'):
        pytest.skip('socket module does not support AF_UNIX')


def _spawn_pageant(  # pragma: no cover
    executable: str | None, env: dict[str, str]
) -> tuple[subprocess.Popen[str], bool] | None:
    """Spawn an isolated Pageant, if possible.

    We attempt to detect whether Pageant is usable, i.e. whether Pageant
    has output buffering problems when announcing its authentication
    socket.

    Args:
        executable:
            The path to the Pageant executable.
        env:
            The new environment for Pageant.  Should typically not
            include an SSH_AUTH_SOCK variable.

    Returns:
        (tuple[subprocess.Popen, bool] | None):
        A 2-tuple `(proc, debug_output)`, where `proc` is the spawned
        Pageant subprocess, and `debug_output` indicates whether Pageant
        will continue to emit debug output (that needs to be actively
        read) or not.

        It is the caller's responsibility to clean up the spawned
        subprocess.

        If the executable is `None`, or if we detect that Pageant is too
        old to properly flush its output, which prevents readers from
        learning the SSH_AUTH_SOCK setting needed to connect to Pageant
        in the first place, then return `None` directly.

    """
    if executable is None:  # pragma: no cover
        return None

    pageant_features = {'flush': False, 'foreground': False}

    # Apparently, Pageant 0.81 and lower running in debug mode does
    # not actively flush its output.  As a result, the first two
    # lines, which set the SSH_AUTH_SOCK and the SSH_AGENT_PID, only
    # print once the output buffer is flushed, whenever that is.
    #
    # This has been reported to the PuTTY developers.
    #
    # For testing purposes, I currently build a version of Pageant with
    # output flushing fixed and with a `--foreground` option.  This is
    # detected here.
    help_output = subprocess.run(
        ['pageant', '--help'],
        executable=executable,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    help_lines = help_output.splitlines(True)
    pageant_version_string = (
        help_lines[1].strip().removeprefix('Release ')
        if len(help_lines) >= 2
        else ''
    )
    v0_81 = packaging.version.Version('0.81')
    if pageant_version_string not in {'', 'Unidentified build'}:
        # TODO(the-13th-letter): Once a fixed Pageant is released,
        # remove the check for build information in the version string.
        # https://github.com/the-13th-letter/derivepassphrase/issues/14
        pageant_version_string_numeric, local_segment_list = (
            pageant_version_string.split('+', 1)
            if '+' in pageant_version_string
            else (pageant_version_string, '')
        )
        local_segments = frozenset(local_segment_list.split('+'))
        pageant_version = packaging.version.Version(
            pageant_version_string_numeric
        )
        for key in pageant_features:
            pageant_features[key] = pageant_version > v0_81 or (
                pageant_version == v0_81 and key in local_segments
            )

    if not pageant_features['flush']:  # pragma: no cover
        return None

    # Because Pageant's debug mode prints debugging information on
    # standard output, and because we yield control to a different
    # thread of execution, we cannot read-and-discard Pageant's output
    # here.  Instead, spawn a consumer process and connect it to
    # Pageant's standard output; see _spawn_data_sink.
    #
    # This will hopefully not be necessary with newer Pageants:
    # a feature request for a `--foreground` option that just avoids the
    # forking behavior has been submitted.

    return subprocess.Popen(
        [
            'pageant',
            '--foreground' if pageant_features['foreground'] else '--debug',
            '-s',
        ],
        executable=executable,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        shell=False,
        env=env,
        text=True,
        bufsize=1,
    ), not pageant_features['foreground']


def _spawn_openssh_agent(  # pragma: no cover
    executable: str | None, env: dict[str, str]
) -> tuple[subprocess.Popen[str], Literal[False]] | None:
    """Spawn an isolated OpenSSH agent, if possible.

    We attempt to detect whether Pageant is usable, i.e. whether Pageant
    has output buffering problems when announcing its authentication
    socket.

    Args:
        executable:
            The path to the OpenSSH agent executable.
        env:
            The new environment for the OpenSSH agent.  Should typically
            not include an SSH_AUTH_SOCK variable.

    Returns:
        (tuple[subprocess.Popen, Literal[False]] | None):
        A 2-tuple `(proc, debug_output)`, where `proc` is the spawned
        OpenSSH agent subprocess, and `debug_output` indicates whether
        the OpenSSH agent will continue to emit debug output that needs
        to be actively read (which it doesn't, so this is always false).

        It is the caller's responsibility to clean up the spawned
        subprocess.

        If the executable is `None`, then return `None` directly.

    """
    if executable is None:
        return None
    return subprocess.Popen(
        ['ssh-agent', '-D', '-s'],
        executable=executable,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        shell=False,
        env=env,
        text=True,
        bufsize=1,
    ), False


def _spawn_system_agent(  # pragma: no cover
    executable: str | None, env: dict[str, str]
) -> None:
    """Placeholder function. Does nothing."""


_spawn_handlers = [
    ('pageant', _spawn_pageant, tests.KnownSSHAgent.Pageant),
    ('ssh-agent', _spawn_openssh_agent, tests.KnownSSHAgent.OpenSSHAgent),
    ('(system)', _spawn_system_agent, tests.KnownSSHAgent.UNKNOWN),
]


@pytest.fixture
def running_ssh_agent(  # pragma: no cover
    skip_if_no_af_unix_support: None,
) -> Iterator[tests.RunningSSHAgentInfo]:
    """Ensure a running SSH agent, if possible, as a pytest fixture.

    Check for a running SSH agent, or spawn a new one if possible.  We
    know how to spawn OpenSSH's agent and PuTTY's Pageant.  If spawned
    this way, the agent does not persist beyond the test.

    This fixture can neither guarantee a particular running agent, nor
    can it guarantee a particular set of loaded keys.

    Yields:
        :
            A 2-tuple `(ssh_auth_sock, agent_type)`, where
            `ssh_auth_sock` is the value of the `SSH_AUTH_SOCK`
            environment variable, to be used to connect to the running
            agent, and `agent_type` is the agent type.

    Raises:
        pytest.skip.Exception:
            If no agent is running or can be spawned, skip this test.

    """
    del skip_if_no_af_unix_support
    exit_stack = contextlib.ExitStack()
    Popen = TypeVar('Popen', bound=subprocess.Popen)

    @contextlib.contextmanager
    def terminate_on_exit(proc: Popen) -> Iterator[Popen]:
        try:
            yield proc
        finally:
            proc.terminate()
            proc.wait()

    with pytest.MonkeyPatch.context() as monkeypatch:
        # pytest's fixture system does not seem to guarantee that
        # environment variables are set up correctly if nested and
        # parametrized fixtures are used: it is possible that "outer"
        # parametrized fixtures are torn down only after other "outer"
        # fixtures of the same parameter set have run.  So set
        # SSH_AUTH_SOCK explicitly to the value saved at interpreter
        # startup.  This is then verified with *a lot* of further assert
        # statements.
        if startup_ssh_auth_sock:  # pragma: no cover
            monkeypatch.setenv('SSH_AUTH_SOCK', startup_ssh_auth_sock)
        else:  # pragma: no cover
            monkeypatch.delenv('SSH_AUTH_SOCK', raising=False)
        for exec_name, spawn_func, agent_type in _spawn_handlers:
            # Use match/case here once Python 3.9 becomes unsupported.
            if exec_name == '(system)':
                assert (
                    os.environ.get('SSH_AUTH_SOCK', None)
                    == startup_ssh_auth_sock
                ), 'SSH_AUTH_SOCK mismatch when checking for running agent'
                try:
                    with ssh_agent.SSHAgentClient() as client:
                        client.list_keys()
                except (KeyError, OSError):
                    continue
                yield tests.RunningSSHAgentInfo(
                    os.environ['SSH_AUTH_SOCK'], agent_type
                )
                assert (
                    os.environ.get('SSH_AUTH_SOCK', None)
                    == startup_ssh_auth_sock
                ), 'SSH_AUTH_SOCK mismatch after returning from running agent'
            else:
                assert (
                    os.environ.get('SSH_AUTH_SOCK', None)
                    == startup_ssh_auth_sock
                ), f'SSH_AUTH_SOCK mismatch when checking for spawnable {exec_name}'  # noqa: E501
                spawn_data = spawn_func(  # type: ignore[operator]
                    executable=shutil.which(exec_name), env={}
                )
                if spawn_data is None:
                    continue
                proc: subprocess.Popen[str]
                emits_debug_output: bool
                proc, emits_debug_output = spawn_data
                with exit_stack:
                    exit_stack.enter_context(terminate_on_exit(proc))
                    assert (
                        os.environ.get('SSH_AUTH_SOCK', None)
                        == startup_ssh_auth_sock
                    ), f'SSH_AUTH_SOCK mismatch after spawning {exec_name}'
                    assert proc.stdout is not None
                    ssh_auth_sock_line = proc.stdout.readline()
                    try:
                        ssh_auth_sock = tests.parse_sh_export_line(
                            ssh_auth_sock_line, env_name='SSH_AUTH_SOCK'
                        )
                    except ValueError:  # pragma: no cover
                        continue
                    pid_line = proc.stdout.readline()
                    if (
                        'pid' not in pid_line.lower()
                        and '_pid' not in pid_line.lower()
                    ):  # pragma: no cover
                        pytest.skip(f'Cannot parse agent output: {pid_line!r}')
                    proc2 = _spawn_data_sink(
                        emits_debug_output=emits_debug_output, proc=proc
                    )
                    if proc2 is not None:  # pragma: no cover
                        exit_stack.enter_context(terminate_on_exit(proc2))
                    assert (
                        os.environ.get('SSH_AUTH_SOCK', None)
                        == startup_ssh_auth_sock
                    ), f'SSH_AUTH_SOCK mismatch after spawning {exec_name} helper'  # noqa: E501
                    monkeypatch2 = exit_stack.enter_context(
                        pytest.MonkeyPatch.context()
                    )
                    monkeypatch2.setenv('SSH_AUTH_SOCK', ssh_auth_sock)
                    yield tests.RunningSSHAgentInfo(ssh_auth_sock, agent_type)
                assert (
                    os.environ.get('SSH_AUTH_SOCK', None)
                    == startup_ssh_auth_sock
                ), f'SSH_AUTH_SOCK mismatch after tearing down {exec_name}'
            return
        pytest.skip('No SSH agent running or spawnable')


def _spawn_data_sink(  # pragma: no cover
    emits_debug_output: bool, *, proc: subprocess.Popen[str]
) -> subprocess.Popen[str] | None:
    """Spawn a data sink to read and discard standard input.

    Necessary for certain SSH agents that emit copious debugging output.

    On UNIX, we can use `cat`, redirected to `/dev/null`.  Otherwise,
    the most robust thing to do is to spawn Python and repeatedly call
    `.read()` on `sys.stdin.buffer`.

    """
    if not emits_debug_output:
        return None
    if proc.stdout is None:
        return None
    sink_script = textwrap.dedent("""
    import sys
    while sys.stdin.buffer.read(4096):
        pass
    """)
    return subprocess.Popen(
        (
            ['cat']
            if os.name == 'posix'
            else [sys.executable or 'python3', '-c', sink_script]
        ),
        executable=sys.executable or None,
        stdin=proc.stdout.fileno(),
        stdout=subprocess.DEVNULL,
        shell=False,
        text=True,
    )


@pytest.fixture(params=_spawn_handlers, ids=operator.itemgetter(0))
def spawn_ssh_agent(  # noqa: C901
    request: pytest.FixtureRequest,
    skip_if_no_af_unix_support: None,
) -> Iterator[tests.SpawnedSSHAgentInfo]:
    """Spawn an isolated SSH agent, if possible, as a pytest fixture.

    Spawn a new SSH agent isolated from other SSH use by other
    processes, if possible.  We know how to spawn OpenSSH's agent and
    PuTTY's Pageant, and the "(system)" fallback agent.

    Yields:
        (tests.SpawnedSSHAgentInfo):
            A [named tuple][collections.namedtuple] containing
            information about the spawned agent, e.g. the software
            product, a client connected to the agent, and whether the
            agent is isolated from other clients.

    Raises:
        pytest.skip.Exception:
            If the agent cannot be spawned, skip this test.

    """
    del skip_if_no_af_unix_support
    agent_env = os.environ.copy()
    agent_env.pop('SSH_AUTH_SOCK', None)
    exit_stack = contextlib.ExitStack()
    Popen = TypeVar('Popen', bound=subprocess.Popen)

    @contextlib.contextmanager
    def terminate_on_exit(proc: Popen) -> Iterator[Popen]:
        try:
            yield proc
        finally:
            proc.terminate()
            proc.wait()

    with pytest.MonkeyPatch.context() as monkeypatch:
        # pytest's fixture system does not seem to guarantee that
        # environment variables are set up correctly if nested and
        # parametrized fixtures are used: it is possible that "outer"
        # parametrized fixtures are torn down only after other "outer"
        # fixtures of the same parameter set have run.  So set
        # SSH_AUTH_SOCK explicitly to the value saved at interpreter
        # startup.  This is then verified with *a lot* of further assert
        # statements.
        if startup_ssh_auth_sock:  # pragma: no cover
            monkeypatch.setenv('SSH_AUTH_SOCK', startup_ssh_auth_sock)
        else:  # pragma: no cover
            monkeypatch.delenv('SSH_AUTH_SOCK', raising=False)
        exec_name, spawn_func, agent_type = request.param
        # Use match/case here once Python 3.9 becomes unsupported.
        if exec_name == '(system)':
            assert (
                os.environ.get('SSH_AUTH_SOCK', None) == startup_ssh_auth_sock
            ), 'SSH_AUTH_SOCK mismatch when checking for running agent'
            try:
                client = ssh_agent.SSHAgentClient()
                client.list_keys()
            except KeyError:  # pragma: no cover
                pytest.skip('SSH agent is not running')
            except OSError as exc:  # pragma: no cover
                pytest.skip(
                    f'Cannot talk to SSH agent: '
                    f'{exc.strerror}: {exc.filename!r}'
                )
            with client:
                assert (
                    os.environ.get('SSH_AUTH_SOCK', None)
                    == startup_ssh_auth_sock
                ), 'SSH_AUTH_SOCK mismatch before setting up for running agent'
                yield tests.SpawnedSSHAgentInfo(agent_type, client, False)
            assert (
                os.environ.get('SSH_AUTH_SOCK', None) == startup_ssh_auth_sock
            ), 'SSH_AUTH_SOCK mismatch after returning from running agent'
            return

        else:
            assert (
                os.environ.get('SSH_AUTH_SOCK', None) == startup_ssh_auth_sock
            ), f'SSH_AUTH_SOCK mismatch when checking for spawnable {exec_name}'  # noqa: E501
            spawn_data = spawn_func(
                executable=shutil.which(exec_name), env=agent_env
            )
            assert (
                os.environ.get('SSH_AUTH_SOCK', None) == startup_ssh_auth_sock
            ), f'SSH_AUTH_SOCK mismatch after spawning {exec_name}'
            if spawn_data is None:  # pragma: no cover
                pytest.skip(f'Cannot spawn usable {exec_name}')
            proc, emits_debug_output = spawn_data
            with exit_stack:
                exit_stack.enter_context(terminate_on_exit(proc))
                assert proc.stdout is not None
                ssh_auth_sock_line = proc.stdout.readline()
                try:
                    ssh_auth_sock = tests.parse_sh_export_line(
                        ssh_auth_sock_line, env_name='SSH_AUTH_SOCK'
                    )
                except ValueError:  # pragma: no cover
                    pytest.skip(
                        f'Cannot parse agent output: {ssh_auth_sock_line}'
                    )
                pid_line = proc.stdout.readline()
                if (
                    'pid' not in pid_line.lower()
                    and '_pid' not in pid_line.lower()
                ):  # pragma: no cover
                    pytest.skip(f'Cannot parse agent output: {pid_line!r}')
                assert (
                    os.environ.get('SSH_AUTH_SOCK', None)
                    == startup_ssh_auth_sock
                ), f'SSH_AUTH_SOCK mismatch before spawning {exec_name} helper'
                proc2 = _spawn_data_sink(
                    emits_debug_output=emits_debug_output, proc=proc
                )
                if proc2 is not None:  # pragma: no cover
                    exit_stack.enter_context(terminate_on_exit(proc2))
                assert (
                    os.environ.get('SSH_AUTH_SOCK', None)
                    == startup_ssh_auth_sock
                ), f'SSH_AUTH_SOCK mismatch after spawning {exec_name} helper'
                monkeypatch2 = exit_stack.enter_context(
                    pytest.MonkeyPatch.context()
                )
                monkeypatch2.setenv('SSH_AUTH_SOCK', ssh_auth_sock)
                try:
                    client = ssh_agent.SSHAgentClient()
                except OSError as exc:  # pragma: no cover
                    pytest.skip(
                        f'Cannot talk to SSH agent: '
                        f'{exc.strerror}: {exc.filename!r}'
                    )
                exit_stack.enter_context(client)
                yield tests.SpawnedSSHAgentInfo(agent_type, client, True)
            assert (
                os.environ.get('SSH_AUTH_SOCK', None) == startup_ssh_auth_sock
            ), f'SSH_AUTH_SOCK mismatch after tearing down {exec_name}'
            return


@pytest.fixture
def ssh_agent_client_with_test_keys_loaded(  # noqa: C901
    spawn_ssh_agent: tests.SpawnedSSHAgentInfo,
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
        (ssh_agent.SSHAgentClient):
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
        It is the fixture's responsibility to clean up the SSH agent
        client after the test.  Closing the client's socket connection
        beforehand (e.g. by using the client as a context manager) may
        lead to exceptions being thrown upon fixture teardown.

    """
    agent_type, client, isolated = spawn_ssh_agent
    all_test_keys = {**tests.SUPPORTED_KEYS, **tests.UNSUITABLE_KEYS}
    successfully_loaded_keys: set[str] = set()

    def prepare_payload(
        payload: bytes | bytearray,
        *,
        isolated: bool = True,
        time_to_live: int = 30,
    ) -> tuple[_types.SSH_AGENTC, bytes]:
        return_code = (
            _types.SSH_AGENTC.ADD_IDENTITY
            if isolated
            else _types.SSH_AGENTC.ADD_ID_CONSTRAINED
        )
        lifetime_constraint = (
            b''
            if isolated
            else b'\x01' + ssh_agent.SSHAgentClient.uint32(time_to_live)
        )
        return (return_code, bytes(payload) + lifetime_constraint)

    try:
        for key_type, key_struct in all_test_keys.items():
            try:
                private_key_data = key_struct['private_key_blob']
            except KeyError:  # pragma: no cover
                continue
            request_code, payload = prepare_payload(
                private_key_data, isolated=isolated, time_to_live=30
            )
            try:
                try:
                    client.request(
                        request_code,
                        payload,
                        response_code=_types.SSH_AGENT.SUCCESS,
                    )
                except ssh_agent.SSHAgentFailedError:  # pragma: no cover
                    # Pageant can fail to accept a key for two separate
                    # reasons:
                    #
                    # - Pageant refuses to accept a key it already holds
                    #   in memory.  Verify this by listing key
                    # - Pageant does not support key constraints (see
                    #   references below).
                    #
                    # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/pageant-timeout.html
                    # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/pageant-key-confirm.html
                    current_loaded_keys = frozenset({
                        pair.key for pair in client.list_keys()
                    })
                    if agent_type == tests.KnownSSHAgent.Pageant and (
                        key_struct['public_key_data'] in current_loaded_keys
                    ):
                        pass
                    elif agent_type == tests.KnownSSHAgent.Pageant and (
                        not isolated
                    ):
                        request_code, payload = prepare_payload(
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
            ):  # pragma: no cover
                pass
            else:  # pragma: no cover
                successfully_loaded_keys.add(key_type)
        yield client
    finally:
        for key_type, key_struct in all_test_keys.items():
            if not isolated and (
                key_type in successfully_loaded_keys
            ):  # pragma: no cover
                # The public key blob is the base64-encoded part in
                # the "public key line".
                public_key = base64.standard_b64decode(
                    key_struct['public_key'].split(None, 2)[1]
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
