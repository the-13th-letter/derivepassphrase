# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""`pytest` testing machinery for the `derivepassphrase` test suite.

This is all the `pytest`-specific data and functionality used in the
`derivepassphrase` test suite; this includes `pytest` marks and
monkeypatched functions (or functions relying heavily internally on
monkeypatching).

All code requiring *more* than plain `pytest` lives in its own sibling
module, e.g., the `hypothesis`-related stuff lives in the [`hypothesis`
sibling module][tests.machinery.hypothesis].

"""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import types
import zipfile
from typing import TYPE_CHECKING

import pytest
from typing_extensions import assert_never, overload

import tests.data
import tests.machinery
from derivepassphrase import _types, ssh_agent
from derivepassphrase._internals import cli_helpers, cli_machinery
from derivepassphrase.ssh_agent import socketprovider

__all__ = ()

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Sequence
    from contextlib import AbstractContextManager

    from typing_extensions import Any


# Marks
# =====


skip_if_cryptography_support = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is not None,
    reason='cryptography support available; cannot test "no support" scenario',
)
"""
A cached pytest mark to skip this test if cryptography support is
available.  Usually this means that the test targets
`derivepassphrase`'s fallback functionality, which is not available
whenever the primary functionality is.
"""
skip_if_no_cryptography_support = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason='no "cryptography" support',
)
"""
A cached pytest mark to skip this test if cryptography support is not
available.  Usually this means that the test targets the
`derivepassphrase export vault` subcommand, whose functionality depends
on cryptography support being available.
"""
skip_if_on_the_annoying_os = pytest.mark.skipif(
    sys.platform == "win32",
    reason="The Annoying OS behaves differently.",
)
"""
A cached pytest mark to skip this test if running on The Annoying
Operating System, a.k.a. Microsoft Windows.  Usually this is due to
unnecessary and stupid differences in the OS internals, and these
differences are deemed irreconcilable in the context of the decorated
test, so the test is to be skipped.

See also:
    [`xfail_on_the_annoying_os`][]

"""
skip_if_no_multiprocessing_support = pytest.mark.skipif(
    importlib.util.find_spec("multiprocessing") is None,
    reason='no "multiprocessing" support',
)
"""
A cached pytest mark to skip this test if multiprocessing support is not
available.  Usually this means that the test targets the concurrency
features of `derivepassphrase`, which is generally only possible to test
in separate processes because the testing machinery operates on
process-global state.
"""


def xfail_on_the_annoying_os(
    f: Callable | None = None,
    /,
    *,
    reason: str = "",
) -> pytest.MarkDecorator | Any:  # pragma: no cover
    """Annotate a test which fails on The Annoying OS.

    Annotate a test to indicate that it fails on The Annoying Operating
    System, a.k.a. Microsoft Windows.  Usually this is due to
    differences in the design of OS internals, and usually, these
    differences are both unnecessary and stupid.

    Args:
        f:
            A callable to decorate.  If not given, return the pytest
            mark directly.
        reason:
            An optional, more detailed reason stating why this test
            fails on The Annoying OS.

    Returns:
        The callable, marked as an expected failure on the Annoying OS,
        or alternatively a suitable pytest mark if no callable was
        passed.  The reason will begin with the phrase "The Annoying OS
        behaves differently.", and the optional detailed reason, if not
        empty, will follow.

    """
    import hypothesis  # noqa: PLC0415

    base_reason = "The Annoying OS behaves differently."
    full_reason = base_reason if not reason else f"{base_reason}  {reason}"
    mark = pytest.mark.xfail(
        sys.platform == "win32",
        reason=full_reason,
        raises=(AssertionError, hypothesis.errors.FailedHealthCheck),
        strict=True,
    )
    return mark if f is None else mark(f)


heavy_duty = pytest.mark.heavy_duty
"""
Test functions/classes/modules with this `pytest` mark are slow, heavy
duty tests.  Users who are impatient (or otherwise cannot afford to wait
for these tests to complete) may wish to exclude these tests; this mark
helps in achieving that.
"""

correctness_focused = pytest.mark.correctness_focused
"""
Test functions/classes/modules with this `pytest` mark are designed
primarily to verify correctness and to find novel failure cases, even at
the cost of high CPU or wall clock time.

Contrast this with tests designed primarily to verify that the existing
system still behaves as before in all the important ways ("is healthy")
even after introducing a small change, but before committing it.  (See
[Two kinds of testing][TWO_KINDS] for more elaboration.)

[TWO_KINDS]: https://blog.nelhage.com/post/two-kinds-of-testing/
"""

non_isolated_agent_use = pytest.mark.xdist_group("non_isolated_agent_use")
"""
Tests with this `pytest` mark (for use with xdist's "loadgroup"
scheduling), comprise the group of tests that use a potentially
non-isolated agent, and thus need to be run serially, in the same worker
(because of the setup and teardown).

This is a pessimistic approach: all agent use is marked with this mark
*unless* we know for sure that this constellation is guaranteed safe.
To date, this is only the case for the fake agents from this very test
suite.

The use of this mark is, if not outright a hack, at least an abuse of
xdist features.  The "correct" way to handle this situation is to employ
a lock, but we have had bad experiences with trying to do this in
a portable way without adding oodles of extra code (that also needs to be
tested), or effectively forcing *everything* into serial execution.  It
also only works because we have precisely one group, and because we have
no work stealing (at least, not with the only scheduler that honors
`xdist_group`).  In particular, it bars us from adding more groups or
grouping along different criteria.
"""


# Parameter sets
# ==============


class Parametrize(types.SimpleNamespace):
    VAULT_CONFIG_FORMATS_DATA = pytest.mark.parametrize(
        ["config", "format", "config_data"],
        [
            pytest.param(
                tests.data.VAULT_V02_CONFIG,
                "v0.2",
                tests.data.VAULT_V02_CONFIG_DATA,
                id="0.2",
            ),
            pytest.param(
                tests.data.VAULT_V03_CONFIG,
                "v0.3",
                tests.data.VAULT_V03_CONFIG_DATA,
                id="0.3",
            ),
            pytest.param(
                tests.data.VAULT_STOREROOM_CONFIG_ZIPPED,
                "storeroom",
                tests.data.VAULT_STOREROOM_CONFIG_DATA,
                id="storeroom",
            ),
        ],
    )


# Monkeypatchings
# ===============


@contextlib.contextmanager
def faked_entry_point_list(  # noqa: C901
    additional_entry_points: Sequence[importlib.metadata.EntryPoint],
    remove_conflicting_entries: bool = False,
) -> Generator[Sequence[str], None, None]:
    """Yield a context where additional entry points are visible.

    Args:
        additional_entry_points:
            A sequence of entry point objects that should additionally
            be visible.
        remove_conflicting_entries:
            If true, remove all names provided by the additional entry
            points, otherwise leave them untouched.

    Yields:
        A sequence of registry names that are newly available within the
        context.

    """
    true_entry_points = importlib.metadata.entry_points()
    additional_entry_points = list(additional_entry_points)

    if sys.version_info >= (3, 12):
        new_entry_points = importlib.metadata.EntryPoints(
            list(true_entry_points) + additional_entry_points
        )

        @overload
        def mangled_entry_points(
            *, group: None = None
        ) -> importlib.metadata.EntryPoints: ...

        @overload
        def mangled_entry_points(
            *, group: str
        ) -> importlib.metadata.EntryPoints: ...

        def mangled_entry_points(
            **params: Any,
        ) -> importlib.metadata.EntryPoints:
            return new_entry_points.select(**params)

    elif sys.version_info >= (3, 10):
        # Compatibility concerns within importlib.metadata: depending on
        # whether the .select() API is used, the result is either the dict
        # of groups of points (as in < 3.10), or the EntryPoints iterable
        # (as in >= 3.12).  So our wrapper needs to duplicate that
        # interface.  FUN.
        new_entry_points_dict = {
            k: list(v) for k, v in true_entry_points.items()
        }
        for ep in additional_entry_points:
            new_entry_points_dict.setdefault(ep.group, []).append(ep)
        new_entry_points = importlib.metadata.EntryPoints([
            ep for group in new_entry_points_dict.values() for ep in group
        ])

        @overload
        def mangled_entry_points(
            *, group: None = None
        ) -> dict[
            str,
            list[importlib.metadata.EntryPoint]
            | tuple[importlib.metadata.EntryPoint, ...],
        ]: ...

        @overload
        def mangled_entry_points(
            *, group: str
        ) -> importlib.metadata.EntryPoints: ...

        def mangled_entry_points(
            **params: Any,
        ) -> (
            importlib.metadata.EntryPoints
            | dict[
                str,
                list[importlib.metadata.EntryPoint]
                | tuple[importlib.metadata.EntryPoint, ...],
            ]
        ):
            return (
                new_entry_points.select(**params)
                if params
                else new_entry_points_dict
            )

    else:
        new_entry_points: dict[
            str,
            list[importlib.metadata.EntryPoint]
            | tuple[importlib.metadata.EntryPoint, ...],
        ] = {
            group_name: list(group)
            for group_name, group in true_entry_points.items()
        }
        for ep in additional_entry_points:
            new_entry_points.setdefault(ep.group, [])
            new_entry_points[ep.group].append(ep)
        new_entry_points = {
            group_name: tuple(group)
            for group_name, group in new_entry_points.items()
        }

        @overload
        def mangled_entry_points(
            *, group: None = None
        ) -> dict[str, tuple[importlib.metadata.EntryPoint, ...]]: ...

        @overload
        def mangled_entry_points(
            *, group: str
        ) -> tuple[importlib.metadata.EntryPoint, ...]: ...

        def mangled_entry_points(
            *, group: str | None = None
        ) -> (
            dict[str, tuple[importlib.metadata.EntryPoint, ...]]
            | tuple[importlib.metadata.EntryPoint, ...]
        ):
            return (
                new_entry_points.get(group, ())
                if group is not None
                else new_entry_points
            )

    registry = socketprovider.SocketProvider.registry
    new_registry = registry.copy()
    keys = [ep.load().key for ep in additional_entry_points]
    aliases = [a for ep in additional_entry_points for a in ep.load().aliases]
    if remove_conflicting_entries:  # pragma: no cover [unused]
        for name in [*keys, *aliases]:
            new_registry.pop(name, None)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            socketprovider.SocketProvider, "registry", new_registry
        )
        monkeypatch.setattr(
            importlib.metadata, "entry_points", mangled_entry_points
        )
        yield (*keys, *aliases)


@contextlib.contextmanager
def isolated_config(
    monkeypatch: pytest.MonkeyPatch,
    runner: tests.machinery.CliRunner,
    main_config_str: str | None = None,
) -> Generator[None, None, None]:
    """Provide an isolated configuration setup, as a context.

    This context manager sets up (and changes into) a temporary
    directory, which holds the user configuration specified in
    `main_config_str`, if any.  The manager also ensures that the
    environment variables `HOME` and `USERPROFILE` are set, and that
    `DERIVEPASSPHRASE_PATH` is unset.  Upon exiting the context, the
    changes are undone and the temporary directory is removed.

    Args:
        monkeypatch:
            A monkeypatch fixture object.
        runner:
            A `click` CLI runner harness.
        main_config_str:
            Optional TOML file contents, to be used as the user
            configuration.

    Returns:
        A context manager, without a return value.

    """
    prog_name = cli_helpers.PROG_NAME
    env_name = prog_name.replace(" ", "_").upper() + "_PATH"
    # TODO(the-13th-letter): Rewrite using parenthesized with-statements.
    # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
    with contextlib.ExitStack() as stack:
        stack.enter_context(runner.isolated_filesystem())
        stack.enter_context(
            cli_machinery.StandardCLILogging.ensure_standard_logging()
        )
        stack.enter_context(
            cli_machinery.StandardCLILogging.ensure_standard_warnings_logging()
        )
        cwd = str(pathlib.Path.cwd().resolve())
        monkeypatch.setenv("HOME", cwd)
        monkeypatch.setenv("APPDATA", cwd)
        monkeypatch.setenv("LOCALAPPDATA", cwd)
        monkeypatch.delenv(env_name, raising=False)
        config_dir = cli_helpers.config_filename(subsystem=None)
        config_dir.mkdir(parents=True, exist_ok=True)
        if isinstance(main_config_str, str):
            cli_helpers.config_filename("user configuration").write_text(
                main_config_str, encoding="UTF-8"
            )
        try:
            yield
        finally:
            cli_helpers.config_filename("write lock").unlink(missing_ok=True)


@contextlib.contextmanager
def isolated_vault_config(
    monkeypatch: pytest.MonkeyPatch,
    runner: tests.machinery.CliRunner,
    vault_config: Any,
    main_config_str: str | None = None,
) -> Generator[None, None, None]:
    """Provide an isolated vault configuration setup, as a context.

    Uses [`isolated_config`][] internally.  Beyond those actions, this
    manager also loads the specified vault configuration into the
    context.

    Args:
        monkeypatch:
            A monkeypatch fixture object.
        runner:
            A `click` CLI runner harness.
        vault_config:
            A valid vault configuration, to be integrated into the
            context.
        main_config_str:
            Optional TOML file contents, to be used as the user
            configuration.

    Returns:
        A context manager, without a return value.

    """
    with isolated_config(
        monkeypatch=monkeypatch, runner=runner, main_config_str=main_config_str
    ):
        config_filename = cli_helpers.config_filename(subsystem="vault")
        with config_filename.open("w", encoding="UTF-8") as outfile:
            json.dump(vault_config, outfile)
        yield


@contextlib.contextmanager
def isolated_vault_exporter_config(
    monkeypatch: pytest.MonkeyPatch,
    runner: tests.machinery.CliRunner,
    vault_config: str | bytes | None = None,
    vault_key: str | None = None,
) -> Generator[None, None, None]:
    """Provide an isolated vault configuration setup, as a context.

    Works similarly to [`isolated_config`][], except that no user
    configuration is accepted or integrated into the context.  This
    manager also accepts a serialized vault-native configuration and
    a vault encryption key to integrate into the context.

    Args:
        monkeypatch:
            A monkeypatch fixture object.
        runner:
            A `click` CLI runner harness.
        vault_config:
            An optional serialized vault-native configuration, to be
            integrated into the context.  If a text string, then the
            contents are written to the file `.vault`.  If a byte
            string, then it is treated as base64-encoded zip file
            contents, which---once inside the `.vault` directory---will
            be extracted into the current directory.
        vault_key:
            An optional encryption key presumably for the stored
            vault-native configuration.  If given, then the environment
            variable `VAULT_KEY` will be populated with this key while
            the context is active.

    Returns:
        A context manager, without a return value.

    """
    # TODO(the-13th-letter): Remove the fallback implementation.
    # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.10
    if TYPE_CHECKING:
        chdir: Callable[..., AbstractContextManager]
    else:
        try:
            chdir = contextlib.chdir  # type: ignore[attr]
        except AttributeError:

            @contextlib.contextmanager
            def chdir(
                newpath: str | bytes | os.PathLike,
            ) -> Generator[None, None, None]:  # pragma: no branch
                oldpath = pathlib.Path.cwd().resolve()
                os.chdir(newpath)
                try:
                    yield
                finally:
                    os.chdir(oldpath)

    with runner.isolated_filesystem():
        cwd = str(pathlib.Path.cwd().resolve())
        monkeypatch.setenv("HOME", cwd)
        monkeypatch.setenv("USERPROFILE", cwd)
        monkeypatch.delenv(
            cli_helpers.PROG_NAME.replace(" ", "_").upper() + "_PATH",
            raising=False,
        )
        monkeypatch.delenv("VAULT_PATH", raising=False)
        monkeypatch.delenv("VAULT_KEY", raising=False)
        monkeypatch.delenv("LOGNAME", raising=False)
        monkeypatch.delenv("USER", raising=False)
        monkeypatch.delenv("USERNAME", raising=False)
        if vault_key is not None:
            monkeypatch.setenv("VAULT_KEY", vault_key)
        vault_config_path = pathlib.Path(".vault").resolve()
        # TODO(the-13th-letter): Rewrite using structural pattern matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        if isinstance(vault_config, str):
            vault_config_path.write_text(f"{vault_config}\n", encoding="UTF-8")
        elif isinstance(vault_config, bytes):
            vault_config_path.mkdir(parents=True, mode=0o700, exist_ok=True)
            # TODO(the-13th-letter): Rewrite using parenthesized
            # with-statements.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
            with contextlib.ExitStack() as stack:
                stack.enter_context(chdir(vault_config_path))
                tmpzipfile = stack.enter_context(
                    tempfile.NamedTemporaryFile(suffix=".zip")
                )
                for line in vault_config.splitlines():
                    tmpzipfile.write(base64.standard_b64decode(line))
                tmpzipfile.flush()
                tmpzipfile.seek(0, 0)
                with zipfile.ZipFile(tmpzipfile.file) as zipfileobj:
                    zipfileobj.extractall()
        elif vault_config is None:
            pass
        else:  # pragma: no cover
            assert_never(vault_config)
        try:
            yield
        finally:
            cli_helpers.config_filename("write lock").unlink(missing_ok=True)


def ensure_singleton_client_if_non_reentrant_agent(
    *,
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    client: ssh_agent.SSHAgentClient,
) -> None:
    """Mangle SSH agent construction if the spawned agent is non-reentrant.

    Monkeypatch a suitable environment to ensure that constructing a new
    SSH agent client -- usually via the
    [`ssh_agent.SSHAgentClient.ensure_agent_subcontext`][] context
    manager -- doesn't really construct a new client, in case the agent
    is non-reentrant.

    Agent reentrancy is determined by the presence of the
    `non_reentrant_agent` mark.  We change nothing if the agent is
    actually reentrant.

    Args:
        request:
            The `pytest` request fixture.  Needed to get the active
            markers on this test function execution, which detail
            whether the agent is potentially non-reentrant.
        monkeypatch:
            A monkeypatching context to enrich.
        client:
            The singleton SSH agent client that is to be used.

    """
    if (
        request.node.get_closest_marker("non_reentrant_agent") is not None
    ):  # pragma: no cover [external]
        real_ensure_agent_subcontext = (
            ssh_agent.SSHAgentClient.ensure_agent_subcontext
        )

        def ensure_agent_subcontext(
            conn: ssh_agent.SSHAgentClient
            | _types.SSHAgentSocket
            | Sequence[str]
            | None = None,
        ) -> contextlib.AbstractContextManager[ssh_agent.SSHAgentClient]:
            if isinstance(conn, ssh_agent.SSHAgentClient):
                return real_ensure_agent_subcontext(conn)
            return real_ensure_agent_subcontext(client)

        monkeypatch.setattr(
            ssh_agent.SSHAgentClient,
            "ensure_agent_subcontext",
            ensure_agent_subcontext,
        )
