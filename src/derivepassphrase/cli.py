# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

# ruff: noqa: TRY400

"""Command-line interface for derivepassphrase."""

from __future__ import annotations

import base64
import collections
import copy
import enum
import importlib
import inspect
import json
import logging
import os
import sys
import unicodedata
import warnings
from typing import (
    TYPE_CHECKING,
    Callable,
    Literal,
    NoReturn,
    TextIO,
    TypeVar,
    cast,
)

import click
from typing_extensions import (
    Any,
    ParamSpec,
    Self,
    assert_never,
)

import derivepassphrase as dpp
from derivepassphrase import _types, exporter, ssh_agent, vault

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

if TYPE_CHECKING:
    import pathlib
    import socket
    import types
    from collections.abc import (
        Iterator,
        MutableSequence,
        Sequence,
    )

__author__ = dpp.__author__
__version__ = dpp.__version__

__all__ = ('derivepassphrase',)

PROG_NAME = 'derivepassphrase'
KEY_DISPLAY_LENGTH = 50

# Error messages
_INVALID_VAULT_CONFIG = 'Invalid vault config'
_AGENT_COMMUNICATION_ERROR = 'Error communicating with the SSH agent'
_NO_USABLE_KEYS = 'No usable SSH keys were found'
_EMPTY_SELECTION = 'Empty selection'


# Logging
# =======


class ClickEchoStderrHandler(logging.Handler):
    """A [`logging.Handler`][] for `click` applications.

    Outputs log messages to [`sys.stderr`][] via [`click.echo`][].

    """

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record.

        Format the log record, then emit it via [`click.echo`][] to
        [`sys.stderr`][].

        """
        click.echo(self.format(record), err=True)


class CLIofPackageFormatter(logging.Formatter):
    """A [`logging.LogRecord`][] formatter for the CLI of a Python package.

    Assuming a package `PKG` and loggers within the same hierarchy
    `PKG`, format all log records from that hierarchy for proper user
    feedback on the console.  Intended for use with [`click`][CLICK] and
    when `PKG` provides a command-line tool `PKG` and when logs from
    that package should show up as output of the command-line tool.

    Essentially, this prepends certain short strings to the log message
    lines to make them readable as standard error output.

    Because this log output is intended to be displayed on standard
    error as high-level diagnostic output, you are strongly discouraged
    from changing the output format to include more tokens besides the
    log message.  Use a dedicated log file handler instead, without this
    formatter.

    [CLICK]: https://pypi.org/projects/click/

    """

    def __init__(
        self,
        *,
        prog_name: str = PROG_NAME,
        package_name: str | None = None,
    ) -> None:
        self.prog_name = prog_name
        self.package_name = (
            package_name
            if package_name is not None
            else prog_name.lower().replace(' ', '_').replace('-', '_')
        )

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record suitably for standard error console output.

        Prepend the formatted string `"PROG_NAME: LABEL"` to each line
        of the message, where `PROG_NAME` is the program name, and
        `LABEL` depends on the record's level and on the logger name as
        follows:

          * For records at level [`logging.DEBUG`][], `LABEL` is
            `"Debug: "`.
          * For records at level [`logging.INFO`][], `LABEL` is the
            empty string.
          * For records at level [`logging.WARNING`][], `LABEL` is
            `"Deprecation warning: "` if the logger is named
            `PKG.deprecation` (where `PKG` is the package name), else
            `"Warning: "`.
          * For records at level [`logging.ERROR`][] and
            [`logging.CRITICAL`][] `"Error: "`, `LABEL` is `"ERROR: "`.

        The level indication strings at level `WARNING` or above are
        highlighted.  Use [`click.echo`][] to output them and remove
        color output if necessary.

        Args:
            record: A log record.

        Returns:
            A formatted log record.

        Raises:
            AssertionError:
                The log level is not supported.

        """
        preliminary_result = record.getMessage()
        prefix = f'{self.prog_name}: '
        if record.levelname == 'DEBUG':  # pragma: no cover
            level_indicator = 'Debug: '
        elif record.levelname == 'INFO':
            level_indicator = ''
        elif record.levelname == 'WARNING':
            level_indicator = (
                f'{click.style("Deprecation warning", bold=True)}: '
                if record.name.endswith('.deprecation')
                else f'{click.style("Warning", bold=True)}: '
            )
        elif record.levelname in {'ERROR', 'CRITICAL'}:
            level_indicator = ''
        else:  # pragma: no cover
            msg = f'Unsupported logging level: {record.levelname}'
            raise AssertionError(msg)
        return ''.join(
            prefix + level_indicator + line
            for line in preliminary_result.splitlines(True)  # noqa: FBT003
        )


class StandardCLILogging:
    """Set up CLI logging handlers upon instantiation."""

    prog_name = PROG_NAME
    package_name = PROG_NAME.lower().replace(' ', '_').replace('-', '_')
    cli_formatter = CLIofPackageFormatter(
        prog_name=prog_name, package_name=package_name
    )
    cli_handler = ClickEchoStderrHandler()
    cli_handler.addFilter(logging.Filter(name=package_name))
    cli_handler.setFormatter(cli_formatter)
    cli_handler.setLevel(logging.WARNING)
    warnings_handler = ClickEchoStderrHandler()
    warnings_handler.addFilter(logging.Filter(name='py.warnings'))
    warnings_handler.setFormatter(cli_formatter)
    warnings_handler.setLevel(logging.WARNING)

    @classmethod
    def ensure_standard_logging(cls) -> StandardLoggingContextManager:
        """Return a context manager to ensure standard logging is set up."""
        return StandardLoggingContextManager(
            handler=cls.cli_handler,
            root_logger=cls.package_name,
        )

    @classmethod
    def ensure_standard_warnings_logging(
        cls,
    ) -> StandardWarningsLoggingContextManager:
        """Return a context manager to ensure warnings logging is set up."""
        return StandardWarningsLoggingContextManager(
            handler=cls.warnings_handler,
        )


class StandardLoggingContextManager:
    """A reentrant context manager setting up standard CLI logging.

    Ensures that the given handler (defaulting to the CLI logging
    handler) is added to the named logger (defaulting to the root
    logger), and if it had to be added, then that it will be removed
    upon exiting the context.

    Reentrant, but not thread safe, because it temporarily modifies
    global state.

    """

    def __init__(
        self,
        handler: logging.Handler,
        root_logger: str | None = None,
    ) -> None:
        self.handler = handler
        self.root_logger_name = root_logger
        self.base_logger = logging.getLogger(self.root_logger_name)
        self.action_required: MutableSequence[bool] = collections.deque()

    def __enter__(self) -> Self:
        self.action_required.append(
            self.handler not in self.base_logger.handlers
        )
        if self.action_required[-1]:
            self.base_logger.addHandler(self.handler)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> Literal[False]:
        if self.action_required[-1]:
            self.base_logger.removeHandler(self.handler)
        self.action_required.pop()
        return False


class StandardWarningsLoggingContextManager(StandardLoggingContextManager):
    """A reentrant context manager setting up standard warnings logging.

    Ensures that warnings are being diverted to the logging system, and
    that the given handler (defaulting to the CLI logging handler) is
    added to the warnings logger. If the handler had to be added, then
    it will be removed upon exiting the context.

    Reentrant, but not thread safe, because it temporarily modifies
    global state.

    """

    def __init__(
        self,
        handler: logging.Handler,
    ) -> None:
        super().__init__(handler=handler, root_logger='py.warnings')
        self.stack: MutableSequence[
            tuple[
                Callable[
                    [
                        type[BaseException] | None,
                        BaseException | None,
                        types.TracebackType | None,
                    ],
                    None,
                ],
                Callable[
                    [
                        str | Warning,
                        type[Warning],
                        str,
                        int,
                        TextIO | None,
                        str | None,
                    ],
                    None,
                ],
            ]
        ] = collections.deque()

    def __enter__(self) -> Self:
        def showwarning(  # noqa: PLR0913,PLR0917
            message: str | Warning,
            category: type[Warning],
            filename: str,
            lineno: int,
            file: TextIO | None = None,
            line: str | None = None,
        ) -> None:
            if file is not None:  # pragma: no cover
                self.stack[0][1](
                    message, category, filename, lineno, file, line
                )
            else:
                logging.getLogger('py.warnings').warning(
                    str(
                        warnings.formatwarning(
                            message, category, filename, lineno, line
                        )
                    )
                )

        ctx = warnings.catch_warnings()
        exit_func = ctx.__exit__
        ctx.__enter__()
        self.stack.append((exit_func, warnings.showwarning))
        warnings.showwarning = showwarning
        return super().__enter__()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> Literal[False]:
        ret = super().__exit__(exc_type, exc_value, exc_tb)
        val = self.stack.pop()[0](exc_type, exc_value, exc_tb)
        assert not val
        return ret


P = ParamSpec('P')
R = TypeVar('R')


def adjust_logging_level(
    ctx: click.Context,
    /,
    param: click.Parameter | None = None,
    value: int | None = None,
) -> None:
    """Change the logs that are emitted to standard error.

    This modifies the [`StandardCLILogging`][] settings such that log
    records at the respective level are emitted, based on the `param`
    and the `value`.

    """
    # Note: If multiple options use this callback, then we will be
    # called multiple times.  Ensure the runs are idempotent.
    if param is None or value is None or ctx.resilient_parsing:
        return
    StandardCLILogging.cli_handler.setLevel(value)
    logging.getLogger(StandardCLILogging.package_name).setLevel(value)


# Option parsing and grouping
# ===========================


class OptionGroupOption(click.Option):
    """A [`click.Option`][] with an associated group name and group epilog.

    Used by [`CommandWithHelpGroups`][] to print help sections.  Each
    subclass contains its own group name and epilog.

    Attributes:
        option_group_name:
            The name of the option group.  Used as a heading on the help
            text for options in this section.
        epilog:
            An epilog to print after listing the options in this
            section.

    """

    option_group_name: str = ''
    """"""
    epilog: str = ''
    """"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401
        if self.__class__ == __class__:  # type: ignore[name-defined]
            raise NotImplementedError
        super().__init__(*args, **kwargs)


class CommandWithHelpGroups(click.Command):
    """A [`click.Command`][] with support for help/option groups.

    Inspired by [a comment on `pallets/click#373`][CLICK_ISSUE], and
    further modified to support group epilogs.

    [CLICK_ISSUE]: https://github.com/pallets/click/issues/373#issuecomment-515293746

    """

    def format_options(
        self,
        ctx: click.Context,
        formatter: click.HelpFormatter,
    ) -> None:
        r"""Format options on the help listing, grouped into sections.

        This is a callback for [`click.Command.get_help`][] that
        implements the `--help` listing, by calling appropriate methods
        of the `formatter`.  We list all options (like the base
        implementation), but grouped into sections according to the
        concrete [`click.Option`][] subclass being used.  If the option
        is an instance of some subclass of [`OptionGroupOption`][], then
        the section heading and the epilog are taken from the
        [`option_group_name`] [OptionGroupOption.option_group_name] and
        [`epilog`] [OptionGroupOption.epilog] attributes; otherwise, the
        section heading is "Options" (or "Other options" if there are
        other option groups) and the epilog is empty.

        Args:
            ctx:
                The click context.
            formatter:
                The formatter for the `--help` listing.

        """
        help_records: dict[str, list[tuple[str, str]]] = {}
        epilogs: dict[str, str] = {}
        params = self.params[:]
        if (  # pragma: no branch
            (help_opt := self.get_help_option(ctx)) is not None
            and help_opt not in params
        ):
            params.append(help_opt)
        for param in params:
            rec = param.get_help_record(ctx)
            if rec is not None:
                if isinstance(param, OptionGroupOption):
                    group_name = param.option_group_name
                    epilogs.setdefault(group_name, param.epilog)
                else:
                    group_name = ''
                help_records.setdefault(group_name, []).append(rec)
        default_group = help_records.pop('')
        default_group_name = (
            'Other Options' if len(default_group) > 1 else 'Options'
        )
        help_records[default_group_name] = default_group
        for group_name, records in help_records.items():
            with formatter.section(group_name):
                formatter.write_dl(records)
            epilog = inspect.cleandoc(epilogs.get(group_name, ''))
            if epilog:
                formatter.write_paragraph()
                with formatter.indentation():
                    formatter.write_text(epilog)


class LoggingOption(OptionGroupOption):
    """Logging options for the CLI."""

    option_group_name = 'Logging'
    epilog = ''


debug_option = click.option(
    '--debug',
    'logging_level',
    is_flag=True,
    flag_value=logging.DEBUG,
    expose_value=False,
    callback=adjust_logging_level,
    help='also emit debug information (implies --verbose)',
    cls=LoggingOption,
)
verbose_option = click.option(
    '-v',
    '--verbose',
    'logging_level',
    is_flag=True,
    flag_value=logging.INFO,
    expose_value=False,
    callback=adjust_logging_level,
    help='emit extra/progress information to standard error',
    cls=LoggingOption,
)
quiet_option = click.option(
    '-q',
    '--quiet',
    'logging_level',
    is_flag=True,
    flag_value=logging.ERROR,
    expose_value=False,
    callback=adjust_logging_level,
    help='suppress even warnings, emit only errors',
    cls=LoggingOption,
)


def standard_logging_options(f: Callable[P, R]) -> Callable[P, R]:
    """Decorate the function with standard logging click options.

    Adds the three click options `-v`/`--verbose`, `-q`/`--quiet` and
    `--debug`, which issue callbacks to the [`log_info`][],
    [`silence_warnings`][] and [`log_debug`][] functions, respectively.

    Args:
        f: A callable to decorate.

    Returns:
        The decorated callable.

    """
    return debug_option(verbose_option(quiet_option(f)))


# Top-level
# =========


class _DefaultToVaultGroup(click.Group):
    """A helper class to implement the default-to-"vault"-subcommand behavior.

    Modifies internal [`click.MultiCommand`][] methods, and thus is both
    an implementation detail and a kludge.

    """

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        """Resolve a command, but default to "vault" instead of erroring out.

        Based on code from click 8.1, which appears to be essentially
        untouched since at least click 3.2.

        """
        cmd_name = click.utils.make_str(args[0])

        # ORIGINAL COMMENT
        # Get the command
        cmd = self.get_command(ctx, cmd_name)

        # ORIGINAL COMMENT
        # If we can't find the command but there is a normalization
        # function available, we try with that one.
        if (  # pragma: no cover
            cmd is None and ctx.token_normalize_func is not None
        ):
            cmd_name = ctx.token_normalize_func(cmd_name)
            cmd = self.get_command(ctx, cmd_name)

        # ORIGINAL COMMENT
        # If we don't find the command we want to show an error message
        # to the user that it was not provided.  However, there is
        # something else we should do: if the first argument looks like
        # an option we want to kick off parsing again for arguments to
        # resolve things like --help which now should go to the main
        # place.
        if cmd is None and not ctx.resilient_parsing:
            if click.parser.split_opt(cmd_name)[0]:
                self.parse_args(ctx, ctx.args)
            # Instead of calling ctx.fail here, default to "vault", and
            # issue a deprecation warning.
            logger = logging.getLogger(PROG_NAME)
            deprecation = logging.getLogger(f'{PROG_NAME}.deprecation')
            deprecation.warning(
                'A subcommand will be required in v1.0. '
                'See --help for available subcommands.'
            )
            logger.warning('Defaulting to subcommand "vault".')
            cmd_name = 'vault'
            cmd = self.get_command(ctx, cmd_name)
            assert cmd is not None, 'Mandatory subcommand "vault" missing!'
            args = [cmd_name, *args]
        return cmd_name if cmd else None, cmd, args[1:]  # noqa: DOC201


class _TopLevelCLIEntryPoint(_DefaultToVaultGroup):
    """A minor variation of _DefaultToVaultGroup for the top-level command.

    When called as a function, this sets up the environment properly
    before invoking the actual callbacks.  Currently, this means setting
    up the logging subsystem and the delegation of Python warnings to
    the logging subsystem.

    The environment setup can be bypassed by calling the `.main` method
    directly.

    """

    def __call__(  # pragma: no cover
        self,
        *args: Any,  # noqa: ANN401
        **kwargs: Any,  # noqa: ANN401
    ) -> Any:  # noqa: ANN401
        """"""  # noqa: D419
        # Coverage testing is done with the `click.testing` module,
        # which does not use the `__call__` shortcut.  So it is normal
        # that this function is never called, and thus should be
        # excluded from coverage.
        with (
            StandardCLILogging.ensure_standard_logging(),
            StandardCLILogging.ensure_standard_warnings_logging(),
        ):
            return self.main(*args, **kwargs)


@click.group(
    context_settings={
        'help_option_names': ['-h', '--help'],
        'ignore_unknown_options': True,
        'allow_interspersed_args': False,
    },
    epilog=r"""
        Configuration is stored in a directory according to the
        DERIVEPASSPHRASE_PATH variable, which defaults to
        `~/.derivepassphrase` on UNIX-like systems and
        `C:\Users\<user>\AppData\Roaming\Derivepassphrase` on Windows.
    """,
    invoke_without_command=True,
    cls=_TopLevelCLIEntryPoint,
)
@click.version_option(version=dpp.__version__, prog_name=PROG_NAME)
@standard_logging_options
@click.pass_context
def derivepassphrase(ctx: click.Context, /) -> None:
    """Derive a strong passphrase, deterministically, from a master secret.

    Using a master secret, derive a passphrase for a named service,
    subject to constraints e.g. on passphrase length, allowed
    characters, etc.  The exact derivation depends on the selected
    derivation scheme.  For each scheme, it is computationally
    infeasible to discern the master secret from the derived passphrase.
    The derivations are also deterministic, given the same inputs, thus
    the resulting passphrases need not be stored explicitly.  The
    service name and constraints themselves also generally need not be
    kept secret, depending on the scheme.

    The currently implemented subcommands are "vault" (for the scheme
    used by vault) and "export" (for exporting foreign configuration
    data).  See the respective `--help` output for instructions.  If no
    subcommand is given, we default to "vault".

    Deprecation notice: Defaulting to "vault" is deprecated.  Starting
    in v1.0, the subcommand must be specified explicitly.\f

    This is a [`click`][CLICK]-powered command-line interface function,
    and not intended for programmatic use.  Call with arguments
    `['--help']` to see full documentation of the interface.  (See also
    [`click.testing.CliRunner`][] for controlled, programmatic
    invocation.)

    [CLICK]: https://pypi.org/package/click/

    """  # noqa: D301
    logger = logging.getLogger(PROG_NAME)
    deprecation = logging.getLogger(f'{PROG_NAME}.deprecation')
    if ctx.invoked_subcommand is None:
        deprecation.warning(
            'A subcommand will be required in v1.0. '
            'See --help for available subcommands.'
        )
        logger.warning('Defaulting to subcommand "vault".')
        # See definition of click.Group.invoke, non-chained case.
        with ctx:
            sub_ctx = derivepassphrase_vault.make_context(
                'vault', ctx.args, parent=ctx
            )
            with sub_ctx:
                return derivepassphrase_vault.invoke(sub_ctx)
    return None


# Exporter
# ========


@derivepassphrase.group(
    'export',
    context_settings={
        'help_option_names': ['-h', '--help'],
        'ignore_unknown_options': True,
        'allow_interspersed_args': False,
    },
    invoke_without_command=True,
    cls=_DefaultToVaultGroup,
)
@click.version_option(version=dpp.__version__, prog_name=PROG_NAME)
@standard_logging_options
@click.pass_context
def derivepassphrase_export(ctx: click.Context, /) -> None:
    """Export a foreign configuration to standard output.

    Read a foreign system configuration, extract all information from
    it, and export the resulting configuration to standard output.

    The only available subcommand is "vault", which implements the
    vault-native configuration scheme.  If no subcommand is given, we
    default to "vault".

    Deprecation notice: Defaulting to "vault" is deprecated.  Starting
    in v1.0, the subcommand must be specified explicitly.\f

    This is a [`click`][CLICK]-powered command-line interface function,
    and not intended for programmatic use.  Call with arguments
    `['--help']` to see full documentation of the interface.  (See also
    [`click.testing.CliRunner`][] for controlled, programmatic
    invocation.)

    [CLICK]: https://pypi.org/package/click/

    """  # noqa: D301
    logger = logging.getLogger(PROG_NAME)
    deprecation = logging.getLogger(f'{PROG_NAME}.deprecation')
    if ctx.invoked_subcommand is None:
        deprecation.warning(
            'A subcommand will be required in v1.0. '
            'See --help for available subcommands.'
        )
        logger.warning('Defaulting to subcommand "vault".')
        # See definition of click.Group.invoke, non-chained case.
        with ctx:
            sub_ctx = derivepassphrase_export_vault.make_context(
                'vault', ctx.args, parent=ctx
            )
            # Constructing the subcontext above will usually already
            # lead to a click.UsageError, so this block typically won't
            # actually be called.
            with sub_ctx:  # pragma: no cover
                return derivepassphrase_export_vault.invoke(sub_ctx)
    return None


def _load_data(
    fmt: Literal['v0.2', 'v0.3', 'storeroom'],
    path: str | bytes | os.PathLike[str],
    key: bytes,
) -> Any:  # noqa: ANN401
    contents: bytes
    module: types.ModuleType
    # Use match/case here once Python 3.9 becomes unsupported.
    if fmt == 'v0.2':
        module = importlib.import_module(
            'derivepassphrase.exporter.vault_native'
        )
        if module.STUBBED:
            raise ModuleNotFoundError
        with open(path, 'rb') as infile:
            contents = base64.standard_b64decode(infile.read())
        return module.export_vault_native_data(
            contents, key, try_formats=['v0.2']
        )
    elif fmt == 'v0.3':  # noqa: RET505
        module = importlib.import_module(
            'derivepassphrase.exporter.vault_native'
        )
        if module.STUBBED:
            raise ModuleNotFoundError
        with open(path, 'rb') as infile:
            contents = base64.standard_b64decode(infile.read())
        return module.export_vault_native_data(
            contents, key, try_formats=['v0.3']
        )
    elif fmt == 'storeroom':
        module = importlib.import_module('derivepassphrase.exporter.storeroom')
        if module.STUBBED:
            raise ModuleNotFoundError
        return module.export_storeroom_data(path, key)
    else:  # pragma: no cover
        assert_never(fmt)


@derivepassphrase_export.command(
    'vault',
    context_settings={'help_option_names': ['-h', '--help']},
)
@standard_logging_options
@click.option(
    '-f',
    '--format',
    'formats',
    metavar='FMT',
    multiple=True,
    default=('v0.3', 'v0.2', 'storeroom'),
    type=click.Choice(['v0.2', 'v0.3', 'storeroom']),
    help='try the following storage formats, in order (default: v0.3, v0.2)',
)
@click.option(
    '-k',
    '--key',
    metavar='K',
    help=(
        'use K as the storage master key '
        '(default: check the `VAULT_KEY`, `LOGNAME`, `USER` or '
        '`USERNAME` environment variables)'
    ),
)
@click.argument('path', metavar='PATH', required=True)
@click.pass_context
def derivepassphrase_export_vault(
    ctx: click.Context,
    /,
    *,
    path: str | bytes | os.PathLike[str],
    formats: Sequence[Literal['v0.2', 'v0.3', 'storeroom']] = (),
    key: str | bytes | None = None,
) -> None:
    """Export a vault-native configuration to standard output.

    Read the vault-native configuration at PATH, extract all information
    from it, and export the resulting configuration to standard output.
    Depending on the configuration format, PATH may either be a file or
    a directory.  Supports the vault "v0.2", "v0.3" and "storeroom"
    formats.

    If PATH is explicitly given as `VAULT_PATH`, then use the
    `VAULT_PATH` environment variable to determine the correct path.
    (Use `./VAULT_PATH` or similar to indicate a file/directory actually
    named `VAULT_PATH`.)

    """
    logger = logging.getLogger(PROG_NAME)
    if path in {'VAULT_PATH', b'VAULT_PATH'}:
        path = exporter.get_vault_path()
    if key is None:
        key = exporter.get_vault_key()
    elif isinstance(key, str):  # pragma: no branch
        key = key.encode('utf-8')
    for fmt in formats:
        try:
            config = _load_data(fmt, path, key)
        except (
            IsADirectoryError,
            NotADirectoryError,
            ValueError,
            RuntimeError,
        ):
            logger.info('Cannot load as %s: %s', fmt, path)
            continue
        except OSError as exc:
            logger.error(
                'Cannot parse %r as a valid config: %s: %r',
                path,
                exc.strerror,
                exc.filename,
            )
            ctx.exit(1)
        except ModuleNotFoundError:
            # TODO(the-13th-letter): Use backslash continuation.
            # https://github.com/nedbat/coveragepy/issues/1836
            logger.error(
                'Cannot load the required Python module "cryptography".'
            )
            logger.info('pip users: see the "export" extra.')
            ctx.exit(1)
        else:
            if not _types.is_vault_config(config):
                logger.error('Invalid vault config: %r', config)
                ctx.exit(1)
            click.echo(json.dumps(config, indent=2, sort_keys=True))
            break
    else:
        logger.error('Cannot parse %r as a valid config.', path)
        ctx.exit(1)


# Vault
# =====


def _config_filename(
    subsystem: str | None = 'old settings.json',
) -> str | bytes | pathlib.Path:
    """Return the filename of the configuration file for the subsystem.

    The (implicit default) file is currently named `settings.json`,
    located within the configuration directory as determined by the
    `DERIVEPASSPHRASE_PATH` environment variable, or by
    [`click.get_app_dir`][] in POSIX mode.  Depending on the requested
    subsystem, this will usually be a different file within that
    directory.

    Args:
        subsystem:
            Name of the configuration subsystem whose configuration
            filename to return.  If not given, return the old filename
            from before the subcommand migration.  If `None`, return the
            configuration directory instead.

    Raises:
        AssertionError:
            An unknown subsystem was passed.

    Deprecated:
        Since v0.2.0: The implicit default subsystem and the old
        configuration filename are deprecated, and will be removed in v1.0.
        The subsystem will be mandatory to specify.

    """
    path: str | bytes | pathlib.Path
    path = os.getenv(PROG_NAME.upper() + '_PATH') or click.get_app_dir(
        PROG_NAME, force_posix=True
    )
    # Use match/case here once Python 3.9 becomes unsupported.
    if subsystem is None:
        return path
    elif subsystem == 'vault':  # noqa: RET505
        filename = f'{subsystem}.json'
    elif subsystem == 'user configuration':
        filename = 'config.toml'
    elif subsystem == 'old settings.json':
        filename = 'settings.json'
    else:  # pragma: no cover
        msg = f'Unknown configuration subsystem: {subsystem!r}'
        raise AssertionError(msg)
    return os.path.join(path, filename)


def _load_config() -> _types.VaultConfig:
    """Load a vault(1)-compatible config from the application directory.

    The filename is obtained via [`_config_filename`][].  This must be
    an unencrypted JSON file.

    Returns:
        The vault settings.  See [`_types.VaultConfig`][] for details.

    Raises:
        OSError:
            There was an OS error accessing the file.
        ValueError:
            The data loaded from the file is not a vault(1)-compatible
            config.

    """
    filename = _config_filename(subsystem='vault')
    with open(filename, 'rb') as fileobj:
        data = json.load(fileobj)
    if not _types.is_vault_config(data):
        raise ValueError(_INVALID_VAULT_CONFIG)
    return data


def _migrate_and_load_old_config() -> tuple[
    _types.VaultConfig, OSError | None
]:
    """Load and migrate a vault(1)-compatible config.

    The (old) filename is obtained via [`_config_filename`][].  This
    must be an unencrypted JSON file.  After loading, the file is
    migrated to the new standard filename.

    Returns:
        The vault settings, and an optional exception encountered during
        migration.  See [`_types.VaultConfig`][] for details on the
        former.

    Raises:
        OSError:
            There was an OS error accessing the old file.
        ValueError:
            The data loaded from the file is not a vault(1)-compatible
            config.

    """
    new_filename = _config_filename(subsystem='vault')
    old_filename = _config_filename(subsystem='old settings.json')
    with open(old_filename, 'rb') as fileobj:
        data = json.load(fileobj)
    if not _types.is_vault_config(data):
        raise ValueError(_INVALID_VAULT_CONFIG)
    try:
        os.replace(old_filename, new_filename)
    except OSError as exc:
        return data, exc
    else:
        return data, None


def _save_config(config: _types.VaultConfig, /) -> None:
    """Save a vault(1)-compatible config to the application directory.

    The filename is obtained via [`_config_filename`][].  The config
    will be stored as an unencrypted JSON file.

    Args:
        config:
            vault configuration to save.

    Raises:
        OSError:
            There was an OS error accessing or writing the file.
        ValueError:
            The data cannot be stored as a vault(1)-compatible config.

    """
    if not _types.is_vault_config(config):
        raise ValueError(_INVALID_VAULT_CONFIG)
    filename = _config_filename(subsystem='vault')
    filedir = os.path.dirname(os.path.abspath(filename))
    try:
        os.makedirs(filedir, exist_ok=False)
    except FileExistsError:
        if not os.path.isdir(filedir):
            raise  # noqa: DOC501
    with open(filename, 'w', encoding='UTF-8') as fileobj:
        json.dump(config, fileobj)


def _load_user_config() -> dict[str, Any]:
    """Load the user config from the application directory.

    The filename is obtained via [`_config_filename`][].

    Returns:
        The user configuration, as a nested `dict`.

    Raises:
        OSError:
            There was an OS error accessing the file.
        ValueError:
            The data loaded from the file is not a valid configuration
            file.

    """
    filename = _config_filename(subsystem='user configuration')
    with open(filename, 'rb') as fileobj:
        return tomllib.load(fileobj)


def _get_suitable_ssh_keys(
    conn: ssh_agent.SSHAgentClient | socket.socket | None = None, /
) -> Iterator[_types.KeyCommentPair]:
    """Yield all SSH keys suitable for passphrase derivation.

    Suitable SSH keys are queried from the running SSH agent (see
    [`ssh_agent.SSHAgentClient.list_keys`][]).

    Args:
        conn:
            An optional connection hint to the SSH agent.  See
            [`ssh_agent.SSHAgentClient.ensure_agent_subcontext`][].

    Yields:
        Every SSH key from the SSH agent that is suitable for passphrase
        derivation.

    Raises:
        KeyError:
            `conn` was `None`, and the `SSH_AUTH_SOCK` environment
            variable was not found.
        NotImplementedError:
            `conn` was `None`, and this Python does not support
            [`socket.AF_UNIX`][], so the SSH agent client cannot be
            automatically set up.
        OSError:
            `conn` was a socket or `None`, and there was an error
            setting up a socket connection to the agent.
        LookupError:
            No keys usable for passphrase derivation are loaded into the
            SSH agent.
        RuntimeError:
            There was an error communicating with the SSH agent.
        ssh_agent.SSHAgentFailedError:
            The agent failed to supply a list of loaded keys.

    """
    with ssh_agent.SSHAgentClient.ensure_agent_subcontext(conn) as client:
        try:
            all_key_comment_pairs = list(client.list_keys())
        except EOFError as e:  # pragma: no cover
            raise RuntimeError(_AGENT_COMMUNICATION_ERROR) from e
        suitable_keys = copy.copy(all_key_comment_pairs)
        for pair in all_key_comment_pairs:
            key, _comment = pair
            if vault.Vault.is_suitable_ssh_key(key, client=client):
                yield pair
    if not suitable_keys:  # pragma: no cover
        raise LookupError(_NO_USABLE_KEYS)


def _prompt_for_selection(
    items: Sequence[str | bytes],
    heading: str = 'Possible choices:',
    single_choice_prompt: str = 'Confirm this choice?',
) -> int:
    """Prompt user for a choice among the given items.

    Print the heading, if any, then present the items to the user.  If
    there are multiple items, prompt the user for a selection, validate
    the choice, then return the list index of the selected item.  If
    there is only a single item, request confirmation for that item
    instead, and return the correct index.

    Args:
        items:
            The list of items to choose from.
        heading:
            A heading for the list of items, to print immediately
            before.  Defaults to a reasonable standard heading.  If
            explicitly empty, print no heading.
        single_choice_prompt:
            The confirmation prompt if there is only a single possible
            choice.  Defaults to a reasonable standard prompt.

    Returns:
        An index into the items sequence, indicating the user's
        selection.

    Raises:
        IndexError:
            The user made an invalid or empty selection, or requested an
            abort.

    """
    n = len(items)
    if heading:
        click.echo(click.style(heading, bold=True))
    for i, x in enumerate(items, start=1):
        click.echo(click.style(f'[{i}]', bold=True), nl=False)
        click.echo(' ', nl=False)
        click.echo(x)
    if n > 1:
        choices = click.Choice([''] + [str(i) for i in range(1, n + 1)])
        choice = click.prompt(
            f'Your selection? (1-{n}, leave empty to abort)',
            err=True,
            type=choices,
            show_choices=False,
            show_default=False,
            default='',
        )
        if not choice:
            raise IndexError(_EMPTY_SELECTION)
        return int(choice) - 1
    prompt_suffix = (
        ' ' if single_choice_prompt.endswith(tuple('?.!')) else ': '
    )
    try:
        click.confirm(
            single_choice_prompt,
            prompt_suffix=prompt_suffix,
            err=True,
            abort=True,
            default=False,
            show_default=False,
        )
    except click.Abort:
        raise IndexError(_EMPTY_SELECTION) from None
    return 0


def _select_ssh_key(
    conn: ssh_agent.SSHAgentClient | socket.socket | None = None, /
) -> bytes | bytearray:
    """Interactively select an SSH key for passphrase derivation.

    Suitable SSH keys are queried from the running SSH agent (see
    [`ssh_agent.SSHAgentClient.list_keys`][]), then the user is prompted
    interactively (see [`click.prompt`][]) for a selection.

    Args:
        conn:
            An optional connection hint to the SSH agent.  See
            [`ssh_agent.SSHAgentClient.ensure_agent_subcontext`][].

    Returns:
        The selected SSH key.

    Raises:
        KeyError:
            `conn` was `None`, and the `SSH_AUTH_SOCK` environment
            variable was not found.
        NotImplementedError:
            `conn` was `None`, and this Python does not support
            [`socket.AF_UNIX`][], so the SSH agent client cannot be
            automatically set up.
        OSError:
            `conn` was a socket or `None`, and there was an error
            setting up a socket connection to the agent.
        IndexError:
            The user made an invalid or empty selection, or requested an
            abort.
        LookupError:
            No keys usable for passphrase derivation are loaded into the
            SSH agent.
        RuntimeError:
            There was an error communicating with the SSH agent.
        SSHAgentFailedError:
            The agent failed to supply a list of loaded keys.
    """
    suitable_keys = list(_get_suitable_ssh_keys(conn))
    key_listing: list[str] = []
    unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
    for key, comment in suitable_keys:
        keytype = unstring_prefix(key)[0].decode('ASCII')
        key_str = base64.standard_b64encode(key).decode('ASCII')
        remaining_key_display_length = KEY_DISPLAY_LENGTH - 1 - len(keytype)
        key_extract = min(
            key_str,
            '...' + key_str[-remaining_key_display_length:],
            key=len,
        )
        comment_str = comment.decode('UTF-8', errors='replace')
        key_listing.append(f'{keytype} {key_extract}  {comment_str}')
    choice = _prompt_for_selection(
        key_listing,
        heading='Suitable SSH keys:',
        single_choice_prompt='Use this key?',
    )
    return suitable_keys[choice].key


def _prompt_for_passphrase() -> str:
    """Interactively prompt for the passphrase.

    Calls [`click.prompt`][] internally.  Moved into a separate function
    mainly for testing/mocking purposes.

    Returns:
        The user input.

    """
    return cast(
        str,
        click.prompt(
            'Passphrase',
            default='',
            hide_input=True,
            show_default=False,
            err=True,
        ),
    )


def _toml_key(*parts: str) -> str:
    """Return a formatted TOML key, given its parts."""
    def escape(string: str) -> str:
        translated = string.translate({
            0: r'\u0000',
            1: r'\u0001',
            2: r'\u0002',
            3: r'\u0003',
            4: r'\u0004',
            5: r'\u0005',
            6: r'\u0006',
            7: r'\u0007',
            8: r'\b',
            9: r'\t',
            10: r'\n',
            11: r'\u000B',
            12: r'\f',
            13: r'\r',
            14: r'\u000E',
            15: r'\u000F',
            ord('"'): r'\"',
            ord('\\'): r'\\',
            127: r'\u007F',
        })
        return f'"{translated}"' if translated != string else string
    return '.'.join(map(escape, parts))


class _ORIGIN(enum.Enum):
    INTERACTIVE: str = 'interactive input'


def _check_for_misleading_passphrase(
    key: tuple[str, ...] | _ORIGIN,
    value: dict[str, Any],
    *,
    main_config: dict[str, Any],
) -> None:
    form_key = 'unicode-normalization-form'
    default_form: str = main_config.get('vault', {}).get(
        f'default-{form_key}', 'NFC'
    )
    form_dict: dict[str, dict] = main_config.get('vault', {}).get(form_key, {})
    form: Any = (
        default_form
        if isinstance(key, _ORIGIN) or key == ('global',)
        else form_dict.get(key[1], default_form)
    )
    config_key = (
        _toml_key('vault', key[1], form_key)
        if isinstance(key, tuple) and len(key) > 1 and key[1] in form_dict
        else f'vault.default-{form_key}'
    )
    if form not in {'NFC', 'NFD', 'NFKC', 'NFKD'}:
        msg = f'Invalid value {form!r} for config key {config_key}'
        raise AssertionError(msg)
    logger = logging.getLogger(PROG_NAME)
    formatted_key = (
        key.value if isinstance(key, _ORIGIN) else _types.json_path(key)
    )
    if 'phrase' in value:
        phrase = value['phrase']
        if not unicodedata.is_normalized(form, phrase):
            logger.warning(
                (
                    'the %s passphrase is not %s-normalized.  '
                    'Make sure to double-check this is really the '
                    'passphrase you want.'
                ),
                formatted_key,
                form,
                stacklevel=2,
            )


# Concrete option groups used by this command-line interface.
class PasswordGenerationOption(OptionGroupOption):
    """Password generation options for the CLI."""

    option_group_name = 'Password generation'
    epilog = """
        Use NUMBER=0, e.g. "--symbol 0", to exclude a character type
        from the output.
    """


class ConfigurationOption(OptionGroupOption):
    """Configuration options for the CLI."""

    option_group_name = 'Configuration'
    epilog = """
        Use $VISUAL or $EDITOR to configure the spawned editor.
    """


class StorageManagementOption(OptionGroupOption):
    """Storage management options for the CLI."""

    option_group_name = 'Storage management'
    epilog = """
        Using "-" as PATH for standard input/standard output is
        supported.
    """


class CompatibilityOption(OptionGroupOption):
    """Compatibility and incompatibility options for the CLI."""

    option_group_name = 'Options concerning compatibility with other tools'


def _validate_occurrence_constraint(
    ctx: click.Context,
    param: click.Parameter,
    value: Any,  # noqa: ANN401
) -> int | None:
    """Check that the occurrence constraint is valid (int, 0 or larger).

    Args:
        ctx: The `click` context.
        param: The current command-line parameter.
        value: The parameter value to be checked.

    Returns:
        The parsed parameter value.

    Raises:
        click.BadParameter: The parameter value is invalid.

    """
    del ctx  # Unused.
    del param  # Unused.
    if value is None:
        return value
    if isinstance(value, int):
        int_value = value
    else:
        try:
            int_value = int(value, 10)
        except ValueError as e:
            msg = 'not an integer'
            raise click.BadParameter(msg) from e
    if int_value < 0:
        msg = 'not a non-negative integer'
        raise click.BadParameter(msg)
    return int_value


def _validate_length(
    ctx: click.Context,
    param: click.Parameter,
    value: Any,  # noqa: ANN401
) -> int | None:
    """Check that the length is valid (int, 1 or larger).

    Args:
        ctx: The `click` context.
        param: The current command-line parameter.
        value: The parameter value to be checked.

    Returns:
        The parsed parameter value.

    Raises:
        click.BadParameter: The parameter value is invalid.

    """
    del ctx  # Unused.
    del param  # Unused.
    if value is None:
        return value
    if isinstance(value, int):
        int_value = value
    else:
        try:
            int_value = int(value, 10)
        except ValueError as e:
            msg = 'not an integer'
            raise click.BadParameter(msg) from e
    if int_value < 1:
        msg = 'not a positive integer'
        raise click.BadParameter(msg)
    return int_value


DEFAULT_NOTES_TEMPLATE = """\
# Enter notes below the line with the cut mark (ASCII scissors and
# dashes).  Lines above the cut mark (such as this one) will be ignored.
#
# If you wish to clear the notes, leave everything beyond the cut mark
# blank.  However, if you leave the *entire* file blank, also removing
# the cut mark, then the edit is aborted, and the old notes contents are
# retained.
#
# - - - - - >8 - - - - - >8 - - - - - >8 - - - - - >8 - - - - -
"""
DEFAULT_NOTES_MARKER = '# - - - - - >8 - - - - -'


@derivepassphrase.command(
    'vault',
    context_settings={'help_option_names': ['-h', '--help']},
    cls=CommandWithHelpGroups,
    epilog=r"""
        WARNING: There is NO WAY to retrieve the generated passphrases
        if the master passphrase, the SSH key, or the exact passphrase
        settings are lost, short of trying out all possible
        combinations.  You are STRONGLY advised to keep independent
        backups of the settings and the SSH key, if any.

        The configuration is NOT encrypted, and you are STRONGLY
        discouraged from using a stored passphrase.
    """,
)
@click.option(
    '-p',
    '--phrase',
    'use_phrase',
    is_flag=True,
    help='prompts you for your passphrase',
    cls=PasswordGenerationOption,
)
@click.option(
    '-k',
    '--key',
    'use_key',
    is_flag=True,
    help='uses your SSH private key to generate passwords',
    cls=PasswordGenerationOption,
)
@click.option(
    '-l',
    '--length',
    metavar='NUMBER',
    callback=_validate_length,
    help='emits password of length NUMBER',
    cls=PasswordGenerationOption,
)
@click.option(
    '-r',
    '--repeat',
    metavar='NUMBER',
    callback=_validate_occurrence_constraint,
    help='allows maximum of NUMBER repeated adjacent chars',
    cls=PasswordGenerationOption,
)
@click.option(
    '--lower',
    metavar='NUMBER',
    callback=_validate_occurrence_constraint,
    help='includes at least NUMBER lowercase letters',
    cls=PasswordGenerationOption,
)
@click.option(
    '--upper',
    metavar='NUMBER',
    callback=_validate_occurrence_constraint,
    help='includes at least NUMBER uppercase letters',
    cls=PasswordGenerationOption,
)
@click.option(
    '--number',
    metavar='NUMBER',
    callback=_validate_occurrence_constraint,
    help='includes at least NUMBER digits',
    cls=PasswordGenerationOption,
)
@click.option(
    '--space',
    metavar='NUMBER',
    callback=_validate_occurrence_constraint,
    help='includes at least NUMBER spaces',
    cls=PasswordGenerationOption,
)
@click.option(
    '--dash',
    metavar='NUMBER',
    callback=_validate_occurrence_constraint,
    help='includes at least NUMBER "-" or "_"',
    cls=PasswordGenerationOption,
)
@click.option(
    '--symbol',
    metavar='NUMBER',
    callback=_validate_occurrence_constraint,
    help='includes at least NUMBER symbol chars',
    cls=PasswordGenerationOption,
)
@click.option(
    '-n',
    '--notes',
    'edit_notes',
    is_flag=True,
    help='spawn an editor to edit notes for SERVICE',
    cls=ConfigurationOption,
)
@click.option(
    '-c',
    '--config',
    'store_config_only',
    is_flag=True,
    help='saves the given settings for SERVICE or global',
    cls=ConfigurationOption,
)
@click.option(
    '-x',
    '--delete',
    'delete_service_settings',
    is_flag=True,
    help='deletes settings for SERVICE',
    cls=ConfigurationOption,
)
@click.option(
    '--delete-globals',
    is_flag=True,
    help='deletes the global shared settings',
    cls=ConfigurationOption,
)
@click.option(
    '-X',
    '--clear',
    'clear_all_settings',
    is_flag=True,
    help='deletes all settings',
    cls=ConfigurationOption,
)
@click.option(
    '-e',
    '--export',
    'export_settings',
    metavar='PATH',
    help='export all saved settings into file PATH',
    cls=StorageManagementOption,
)
@click.option(
    '-i',
    '--import',
    'import_settings',
    metavar='PATH',
    help='import saved settings from file PATH',
    cls=StorageManagementOption,
)
@click.option(
    '--overwrite-existing/--merge-existing',
    'overwrite_config',
    default=False,
    help='overwrite or merge (default) the existing configuration',
    cls=CompatibilityOption,
)
@click.version_option(version=dpp.__version__, prog_name=PROG_NAME)
@standard_logging_options
@click.argument('service', required=False)
@click.pass_context
def derivepassphrase_vault(  # noqa: C901,PLR0912,PLR0913,PLR0914,PLR0915
    ctx: click.Context,
    /,
    *,
    service: str | None = None,
    use_phrase: bool = False,
    use_key: bool = False,
    length: int | None = None,
    repeat: int | None = None,
    lower: int | None = None,
    upper: int | None = None,
    number: int | None = None,
    space: int | None = None,
    dash: int | None = None,
    symbol: int | None = None,
    edit_notes: bool = False,
    store_config_only: bool = False,
    delete_service_settings: bool = False,
    delete_globals: bool = False,
    clear_all_settings: bool = False,
    export_settings: TextIO | pathlib.Path | os.PathLike[str] | None = None,
    import_settings: TextIO | pathlib.Path | os.PathLike[str] | None = None,
    overwrite_config: bool = False,
) -> None:
    """Derive a passphrase using the vault(1) derivation scheme.

    Using a master passphrase or a master SSH key, derive a passphrase
    for SERVICE, subject to length, character and character repetition
    constraints.  The derivation is cryptographically strong, meaning
    that even if a single passphrase is compromised, guessing the master
    passphrase or a different service's passphrase is computationally
    infeasible.  The derivation is also deterministic, given the same
    inputs, thus the resulting passphrase need not be stored explicitly.
    The service name and constraints themselves also need not be kept
    secret; the latter are usually stored in a world-readable file.

    If operating on global settings, or importing/exporting settings,
    then SERVICE must be omitted.  Otherwise it is required.\f

    This is a [`click`][CLICK]-powered command-line interface function,
    and not intended for programmatic use.  Call with arguments
    `['--help']` to see full documentation of the interface.  (See also
    [`click.testing.CliRunner`][] for controlled, programmatic
    invocation.)

    [CLICK]: https://pypi.org/package/click/

    Parameters:
        ctx (click.Context):
            The `click` context.

    Other Parameters:
        service:
            A service name.  Required, unless operating on global
            settings or importing/exporting settings.
        use_phrase:
            Command-line argument `-p`/`--phrase`.  If given, query the
            user for a passphrase instead of an SSH key.
        use_key:
            Command-line argument `-k`/`--key`.  If given, query the
            user for an SSH key instead of a passphrase.
        length:
            Command-line argument `-l`/`--length`.  Override the default
            length of the generated passphrase.
        repeat:
            Command-line argument `-r`/`--repeat`.  Override the default
            repetition limit if positive, or disable the repetition
            limit if 0.
        lower:
            Command-line argument `--lower`.  Require a given amount of
            ASCII lowercase characters if positive, else forbid ASCII
            lowercase characters if 0.
        upper:
            Command-line argument `--upper`.  Same as `lower`, but for
            ASCII uppercase characters.
        number:
            Command-line argument `--number`.  Same as `lower`, but for
            ASCII digits.
        space:
            Command-line argument `--space`.  Same as `lower`, but for
            the space character.
        dash:
            Command-line argument `--dash`.  Same as `lower`, but for
            the hyphen-minus and underscore characters.
        symbol:
            Command-line argument `--symbol`.  Same as `lower`, but for
            all other ASCII printable characters (except backquote).
        edit_notes:
            Command-line argument `-n`/`--notes`.  If given, spawn an
            editor to edit notes for `service`.
        store_config_only:
            Command-line argument `-c`/`--config`.  If given, saves the
            other given settings (`--key`, ..., `--symbol`) to the
            configuration file, either specifically for `service` or as
            global settings.
        delete_service_settings:
            Command-line argument `-x`/`--delete`.  If given, removes
            the settings for `service` from the configuration file.
        delete_globals:
            Command-line argument `--delete-globals`.  If given, removes
            the global settings from the configuration file.
        clear_all_settings:
            Command-line argument `-X`/`--clear`.  If given, removes all
            settings from the configuration file.
        export_settings:
            Command-line argument `-e`/`--export`.  If a file object,
            then it must be open for writing and accept `str` inputs.
            Otherwise, a filename to open for writing.  Using `-` for
            standard output is supported.
        import_settings:
            Command-line argument `-i`/`--import`.  If a file object, it
            must be open for reading and yield `str` values.  Otherwise,
            a filename to open for reading.  Using `-` for standard
            input is supported.
        overwrite_config:
            Command-line arguments `--overwrite-existing` (True) and
            `--merge-existing` (False).  Controls whether config saving
            and config importing overwrite existing configurations, or
            merge them section-wise instead.

    """  # noqa: D301
    logger = logging.getLogger(PROG_NAME)
    deprecation = logging.getLogger(PROG_NAME + '.deprecation')
    options_in_group: dict[type[click.Option], list[click.Option]] = {}
    params_by_str: dict[str, click.Parameter] = {}
    for param in ctx.command.params:
        if isinstance(param, click.Option):
            group: type[click.Option]
            # Use match/case here once Python 3.9 becomes unsupported.
            if isinstance(param, PasswordGenerationOption):
                group = PasswordGenerationOption
            elif isinstance(param, ConfigurationOption):
                group = ConfigurationOption
            elif isinstance(param, StorageManagementOption):
                group = StorageManagementOption
            elif isinstance(param, LoggingOption):
                group = LoggingOption
            elif isinstance(param, CompatibilityOption):
                group = CompatibilityOption
            elif isinstance(param, OptionGroupOption):
                raise AssertionError(  # noqa: DOC501,TRY003,TRY004
                    f'Unknown option group for {param!r}'  # noqa: EM102
                )
            else:
                group = click.Option
            options_in_group.setdefault(group, []).append(param)
        params_by_str[param.human_readable_name] = param
        for name in param.opts + param.secondary_opts:
            params_by_str[name] = param

    def is_param_set(param: click.Parameter) -> bool:
        return bool(ctx.params.get(param.human_readable_name))

    def check_incompatible_options(
        param: click.Parameter | str,
        *incompatible: click.Parameter | str,
    ) -> None:
        if isinstance(param, str):
            param = params_by_str[param]
        assert isinstance(param, click.Parameter)
        if not is_param_set(param):
            return
        for other in incompatible:
            if isinstance(other, str):
                other = params_by_str[other]  # noqa: PLW2901
            assert isinstance(other, click.Parameter)
            if other != param and is_param_set(other):
                opt_str = param.opts[0]
                other_str = other.opts[0]
                raise click.BadOptionUsage(
                    opt_str, f'mutually exclusive with {other_str}', ctx=ctx
                )

    def err(msg: Any, *args: Any, **kwargs: Any) -> NoReturn:  # noqa: ANN401
        stacklevel = kwargs.pop('stacklevel', 1)
        stacklevel += 1
        logger.error(msg, *args, stacklevel=stacklevel, **kwargs)
        ctx.exit(1)

    def key_to_phrase(key_: str | bytes | bytearray, /) -> bytes | bytearray:
        key = base64.standard_b64decode(key_)
        try:
            with ssh_agent.SSHAgentClient.ensure_agent_subcontext() as client:
                try:
                    return vault.Vault.phrase_from_key(key, conn=client)
                except ssh_agent.SSHAgentFailedError as e:
                    try:
                        keylist = client.list_keys()
                    except ssh_agent.SSHAgentFailedError:
                        pass
                    except Exception as e2:  # noqa: BLE001
                        e.__context__ = e2
                    else:
                        if not any(k == key for k, _ in keylist):
                            err(
                                'The requested SSH key is not loaded '
                                'into the agent.'
                            )
                    err(e)
        except KeyError:
            err('Cannot find running SSH agent; check SSH_AUTH_SOCK')
        except NotImplementedError:
            err(
                'Cannot connect to SSH agent because '
                'this Python version does not support UNIX domain sockets'
            )
        except OSError as e:
            err('Cannot connect to SSH agent: %s', e.strerror)

    def get_config() -> _types.VaultConfig:
        try:
            return _load_config()
        except FileNotFoundError:
            try:
                backup_config, exc = _migrate_and_load_old_config()
            except FileNotFoundError:
                return {'services': {}}
            old_name = os.path.basename(
                _config_filename(subsystem='old settings.json')
            )
            new_name = os.path.basename(_config_filename(subsystem='vault'))
            deprecation.warning(
                (
                    'Using deprecated v0.1-style config file %r, '
                    'instead of v0.2-style %r.  '
                    'Support for v0.1-style config filenames will be '
                    'removed in v1.0.'
                ),
                old_name,
                new_name,
            )
            if isinstance(exc, OSError):
                logger.warning(
                    'Failed to migrate to %r: %s: %r',
                    new_name,
                    exc.strerror,
                    exc.filename,
                )
            else:
                deprecation.info('Successfully migrated to %r.', new_name)
            return backup_config
        except OSError as e:
            err('Cannot load config: %s: %r', e.strerror, e.filename)
        except Exception as e:  # noqa: BLE001
            err('Cannot load config: %s', str(e), exc_info=e)

    def put_config(config: _types.VaultConfig, /) -> None:
        try:
            _save_config(config)
        except OSError as exc:
            err('Cannot store config: %s: %r', exc.strerror, exc.filename)
        except Exception as exc:  # noqa: BLE001
            err('Cannot store config: %s', str(exc), exc_info=exc)

    def get_user_config() -> dict[str, Any]:
        try:
            return _load_user_config()
        except FileNotFoundError:
            return {}
        except OSError as e:
            err('Cannot load user config: %s: %r', e.strerror, e.filename)
        except Exception as e:  # noqa: BLE001
            err('Cannot load user config: %s', str(e), exc_info=e)

    configuration: _types.VaultConfig

    check_incompatible_options('--phrase', '--key')
    for group in (ConfigurationOption, StorageManagementOption):
        for opt in options_in_group[group]:
            if opt != params_by_str['--config']:
                check_incompatible_options(
                    opt, *options_in_group[PasswordGenerationOption]
                )

    for group in (ConfigurationOption, StorageManagementOption):
        for opt in options_in_group[group]:
            check_incompatible_options(
                opt,
                *options_in_group[ConfigurationOption],
                *options_in_group[StorageManagementOption],
            )
    sv_or_global_options = options_in_group[PasswordGenerationOption]
    for param in sv_or_global_options:
        if is_param_set(param) and not (
            service or is_param_set(params_by_str['--config'])
        ):
            opt_str = param.opts[0]
            msg = f'{opt_str} requires a SERVICE or --config'
            raise click.UsageError(msg)  # noqa: DOC501
    sv_options = [params_by_str['--notes'], params_by_str['--delete']]
    for param in sv_options:
        if is_param_set(param) and not service:
            opt_str = param.opts[0]
            msg = f'{opt_str} requires a SERVICE'
            raise click.UsageError(msg)
    no_sv_options = [
        params_by_str['--delete-globals'],
        params_by_str['--clear'],
        *options_in_group[StorageManagementOption],
    ]
    for param in no_sv_options:
        if is_param_set(param) and service:
            opt_str = param.opts[0]
            msg = f'{opt_str} does not take a SERVICE argument'
            raise click.UsageError(msg)

    user_config = get_user_config()

    if service == '':  # noqa: PLC1901
        logger.warning(
            'An empty SERVICE is not supported by vault(1).  '
            'For compatibility, this will be treated as if SERVICE '
            'was not supplied, i.e., it will error out, or '
            'operate on global settings.'
        )

    if edit_notes:
        assert service is not None
        configuration = get_config()
        text = DEFAULT_NOTES_TEMPLATE + configuration['services'].get(
            service, cast(_types.VaultConfigServicesSettings, {})
        ).get('notes', '')
        notes_value = click.edit(text=text)
        if notes_value is not None:
            notes_lines = collections.deque(notes_value.splitlines(True))  # noqa: FBT003
            while notes_lines:
                line = notes_lines.popleft()
                if line.startswith(DEFAULT_NOTES_MARKER):
                    notes_value = ''.join(notes_lines)
                    break
            else:
                if not notes_value.strip():
                    err('Not saving new notes: user aborted request')
            configuration['services'].setdefault(service, {})['notes'] = (
                notes_value.strip('\n')
            )
            put_config(configuration)
    elif delete_service_settings:
        assert service is not None
        configuration = get_config()
        if service in configuration['services']:
            del configuration['services'][service]
            put_config(configuration)
    elif delete_globals:
        configuration = get_config()
        if 'global' in configuration:
            del configuration['global']
            put_config(configuration)
    elif clear_all_settings:
        put_config({'services': {}})
    elif import_settings:
        try:
            # TODO(the-13th-letter): keep track of auto-close; try
            # os.dup if feasible
            infile = (
                cast(TextIO, import_settings)
                if hasattr(import_settings, 'close')
                else click.open_file(os.fspath(import_settings), 'rt')
            )
            with infile:
                maybe_config = json.load(infile)
        except json.JSONDecodeError as e:
            err('Cannot load config: cannot decode JSON: %s', e)
        except OSError as e:
            err('Cannot load config: %s: %r', e.strerror, e.filename)
        cleaned = _types.clean_up_falsy_vault_config_values(maybe_config)
        if not _types.is_vault_config(maybe_config):
            err('Cannot load config: %s', _INVALID_VAULT_CONFIG)
        assert cleaned is not None
        for step in cleaned:
            # These are never fatal errors, because the semantics of
            # vault upon encountering these settings are ill-specified,
            # but not ill-defined.
            if step.action == 'replace':
                logger.warning(
                    'Replacing invalid value %s for key %s with %s.',
                    json.dumps(step.old_value),
                    _types.json_path(step.path),
                    json.dumps(step.new_value),
                )
            else:
                logger.warning(
                    'Removing ineffective setting %s = %s.',
                    _types.json_path(step.path),
                    json.dumps(step.old_value),
                )
        if '' in maybe_config['services']:
            logger.warning(
                (
                    'An empty SERVICE is not supported by vault(1), '
                    'and the empty-string service settings will be '
                    'inaccessible and ineffective.  To ensure that '
                    'vault(1) and %s see the settings, move them '
                    'into the "global" section.'
                ),
                PROG_NAME,
            )
        try:
            _check_for_misleading_passphrase(
                ('global',),
                cast(dict[str, Any], maybe_config.get('global', {})),
                main_config=user_config,
            )
            for key, value in maybe_config['services'].items():
                _check_for_misleading_passphrase(
                    ('services', key),
                    cast(dict[str, Any], value),
                    main_config=user_config,
                )
        except AssertionError as e:
            err('The configuration file is invalid.  ' + str(e))
        if overwrite_config:
            put_config(maybe_config)
        else:
            configuration = get_config()
            merged_config: collections.ChainMap[str, Any] = (
                collections.ChainMap(
                    {
                        'services': collections.ChainMap(
                            maybe_config['services'],
                            configuration['services'],
                        ),
                    },
                    {'global': maybe_config['global']}
                    if 'global' in maybe_config
                    else {},
                    {'global': configuration['global']}
                    if 'global' in configuration
                    else {},
                )
            )
            new_config: Any = {
                k: dict(v) if isinstance(v, collections.ChainMap) else v
                for k, v in sorted(merged_config.items())
            }
            assert _types.is_vault_config(new_config)
            put_config(new_config)
    elif export_settings:
        configuration = get_config()
        try:
            # TODO(the-13th-letter): keep track of auto-close; try
            # os.dup if feasible
            outfile = (
                cast(TextIO, export_settings)
                if hasattr(export_settings, 'close')
                else click.open_file(os.fspath(export_settings), 'wt')
            )
            with outfile:
                json.dump(configuration, outfile)
        except OSError as e:
            err('Cannot store config: %s: %r', e.strerror, e.filename)
    else:
        configuration = get_config()
        # This block could be type checked more stringently, but this
        # would probably involve a lot of code repetition.  Since we
        # have a type guarding function anyway, assert that we didn't
        # make any mistakes at the end instead.
        global_keys = {'key', 'phrase'}
        service_keys = {
            'key',
            'phrase',
            'length',
            'repeat',
            'lower',
            'upper',
            'number',
            'space',
            'dash',
            'symbol',
        }
        settings: collections.ChainMap[str, Any] = collections.ChainMap(
            {
                k: v
                for k, v in locals().items()
                if k in service_keys and v is not None
            },
            cast(
                dict[str, Any],
                configuration['services'].get(service or '', {}),
            ),
            cast(dict[str, Any], configuration.get('global', {})),
        )
        if use_key:
            try:
                key = base64.standard_b64encode(_select_ssh_key()).decode(
                    'ASCII'
                )
            except IndexError:
                err('No valid SSH key selected')
            except KeyError:
                err('Cannot find running SSH agent; check SSH_AUTH_SOCK')
            except NotImplementedError:
                err(
                    'Cannot connect to SSH agent because '
                    'this Python version does not support UNIX domain sockets'
                )
            except OSError as e:
                err('Cannot connect to SSH agent: %s', e.strerror)
            except (
                LookupError,
                RuntimeError,
                ssh_agent.SSHAgentFailedError,
            ) as e:
                err(str(e))
        elif use_phrase:
            maybe_phrase = _prompt_for_passphrase()
            if not maybe_phrase:
                err('No passphrase given')
            else:
                phrase = maybe_phrase
        if store_config_only:
            view: collections.ChainMap[str, Any]
            view = (
                collections.ChainMap(*settings.maps[:2])
                if service
                else collections.ChainMap(settings.maps[0], settings.maps[2])
            )
            if use_key:
                view['key'] = key
            elif use_phrase:
                view['phrase'] = phrase
                settings_type = 'service' if service else 'global'
                try:
                    _check_for_misleading_passphrase(
                        ('services', service) if service else ('global',),
                        {'phrase': phrase},
                        main_config=user_config,
                    )
                except AssertionError as e:
                    err('The configuration file is invalid.  ' + str(e))
                if 'key' in settings:
                    logger.warning(
                        (
                            'Setting a %s passphrase is ineffective '
                            'because a key is also set.'
                        ),
                        settings_type,
                    )
            if not view.maps[0]:
                settings_type = 'service' if service else 'global'
                msg = (
                    f'Cannot update {settings_type} settings without '
                    f'actual settings'
                )
                raise click.UsageError(msg)
            subtree: dict[str, Any] = (
                configuration['services'].setdefault(service, {})  # type: ignore[assignment]
                if service
                else configuration.setdefault('global', {})
            )
            if overwrite_config:
                subtree.clear()
            subtree.update(view)
            assert _types.is_vault_config(
                configuration
            ), f'Invalid vault configuration: {configuration!r}'
            put_config(configuration)
        else:
            if not service:
                msg = 'SERVICE is required'
                raise click.UsageError(msg)
            kwargs: dict[str, Any] = {
                k: v
                for k, v in settings.items()
                if k in service_keys and v is not None
            }

            if use_phrase:
                try:
                    _check_for_misleading_passphrase(
                        _ORIGIN.INTERACTIVE,
                        {'phrase': phrase},
                        main_config=user_config,
                    )
                except AssertionError as e:
                    err('The configuration file is invalid.  ' + str(e))

            # If either --key or --phrase are given, use that setting.
            # Otherwise, if both key and phrase are set in the config,
            # use the key.  Otherwise, if only one of key and phrase is
            # set in the config, use that one.  In all these above
            # cases, set the phrase via vault.Vault.phrase_from_key if
            # a key is given.  Finally, if nothing is set, error out.
            if use_key or use_phrase:
                kwargs['phrase'] = key_to_phrase(key) if use_key else phrase
            elif kwargs.get('key'):
                kwargs['phrase'] = key_to_phrase(kwargs['key'])
            elif kwargs.get('phrase'):
                pass
            else:
                msg = (
                    'No passphrase or key given on command-line '
                    'or in configuration'
                )
                raise click.UsageError(msg)
            kwargs.pop('key', '')
            result = vault.Vault(**kwargs).generate(service)
            click.echo(result.decode('ASCII'))


if __name__ == '__main__':
    derivepassphrase()
