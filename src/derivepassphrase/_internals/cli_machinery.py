# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib


"""Command-line machinery for derivepassphrase.

Warning:
    Non-public module (implementation detail), provided for didactical and
    educational purposes only. Subject to change without notice, including
    removal.

"""

from __future__ import annotations

import collections
import importlib.metadata
import inspect
import logging
import socket
import warnings
from typing import TYPE_CHECKING, Callable, Literal, TextIO, TypeVar

import click
import click.shell_completion
from typing_extensions import Any, ParamSpec, override

from derivepassphrase import _internals, _types
from derivepassphrase._internals import cli_messages as _msg

if TYPE_CHECKING:
    import types
    from collections.abc import (
        MutableSequence,
    )

    from typing_extensions import Self

PROG_NAME = _internals.PROG_NAME
VERSION = _internals.VERSION
VERSION_OUTPUT_WRAPPING_WIDTH = 72

# Error messages
NOT_AN_INTEGER = 'not an integer'
NOT_A_NONNEGATIVE_INTEGER = 'not a non-negative integer'
NOT_A_POSITIVE_INTEGER = 'not a positive integer'


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
        click.echo(
            self.format(record),
            err=True,
            color=getattr(record, 'color', None),
        )


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
            [`logging.CRITICAL`][] `"Error: "`, `LABEL` is the empty
            string.

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
        if record.levelname == 'DEBUG':  # pragma: no cover [unused]
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
        else:  # pragma: no cover [failsafe]
            msg = f'Unsupported logging level: {record.levelname}'
            raise AssertionError(msg)
        parts = [
            ''.join(
                prefix + level_indicator + line
                for line in preliminary_result.splitlines(True)  # noqa: FBT003
            )
        ]
        if record.exc_info:
            parts.append(self.formatException(record.exc_info) + '\n')
        return ''.join(parts)


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
            if file is not None:  # pragma: no cover [external-api]
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

    option_group_name: object = ''
    """"""
    epilog: object = ''
    """"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401
        if self.__class__ == __class__:  # type: ignore[name-defined]
            raise NotImplementedError
        # Though click 8.1 mostly defers help text processing until the
        # `BaseCommand.format_*` methods are called, the Option
        # constructor still preprocesses the help text, and asserts that
        # the help text is a string.  Work around this by removing the
        # help text from the constructor arguments and re-adding it,
        # unprocessed, after constructor finishes.
        unset = object()
        help = kwargs.pop('help', unset)  # noqa: A001
        super().__init__(*args, **kwargs)
        if help is not unset:  # pragma: no branch
            self.help = help


class StandardOption(OptionGroupOption):
    pass


# Portions of this class are based directly on code from click 8.1.
# (This does not in general include docstrings, unless otherwise noted.)
# They are subject to the 3-clause BSD license in the following
# paragraphs.  Modifications to their code are marked with respective
# comments; they too are released under the same license below.  The
# original code did not contain any "noqa" or "pragma" comments.
#
#     Copyright 2024 Pallets
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the
#     following conditions are met:
#
#      1. Redistributions of source code must retain the above
#         copyright notice, this list of conditions and the
#         following disclaimer.
#
#      2. Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the
#         following disclaimer in the documentation and/or other
#         materials provided with the distribution.
#
#      3. Neither the name of the copyright holder nor the names
#         of its contributors may be used to endorse or promote
#         products derived from this software without specific
#         prior written permission.
#
#     THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
#     CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
#     INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#     MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#     DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
#     CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#     SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
#     NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#     LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#     HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#     CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#     OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#     SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
class CommandWithHelpGroups(click.Command):
    """A [`click.Command`][] with support for some help text customizations.

    Supports help/option groups, group epilogs, and help text objects
    (objects that stringify to help texts).  The latter is primarily
    used to implement translations.

    Inspired by [a comment on `pallets/click#373`][CLICK_ISSUE] for
    help/option group support, and further modified to include group
    epilogs and help text objects.

    [CLICK_ISSUE]: https://github.com/pallets/click/issues/373#issuecomment-515293746

    """

    @staticmethod
    def _text(text: object, /) -> str:
        if isinstance(text, (list, tuple)):
            return '\n\n'.join(str(x) for x in text)
        return str(text)

    # This method is based on click 8.1; see the comment above the class
    # declaration for license details.
    def collect_usage_pieces(self, ctx: click.Context) -> list[str]:
        """Return the pieces for the usage string.

        Args:
            ctx:
                The click context.

        """
        rv = [str(self.options_metavar)] if self.options_metavar else []
        for param in self.get_params(ctx):
            rv.extend(str(x) for x in param.get_usage_pieces(ctx))
        return rv

    # This method is based on click 8.1; see the comment above the class
    # declaration for license details.
    def get_help_option(
        self,
        ctx: click.Context,
    ) -> click.Option | None:
        """Return a standard help option object.

        Args:
            ctx:
                The click context.

        """
        help_options = self.get_help_option_names(ctx)

        if (
            not help_options or not self.add_help_option
        ):  # pragma: no cover [external-api]
            return None

        def show_help(
            ctx: click.Context,
            param: click.Parameter,  # noqa: ARG001
            value: str,
        ) -> None:
            if value and not ctx.resilient_parsing:
                click.echo(ctx.get_help(), color=ctx.color)
                ctx.exit()

        # Modified from click 8.1: We use StandardOption and a non-str
        # object as the help string.
        return StandardOption(
            help_options,
            is_flag=True,
            is_eager=True,
            expose_value=False,
            callback=show_help,
            help=_msg.TranslatedString(_msg.Label.HELP_OPTION_HELP_TEXT),
        )

    # This method is based on click 8.1; see the comment above the class
    # declaration for license details.
    def get_short_help_str(
        self,
        limit: int = 45,
    ) -> str:
        """Return the short help string for a command.

        If only a long help string is given, shorten it.

        Args:
            limit:
                The maximum width of the short help string.

        """
        # Modification against click 8.1: Call `_text()` on `self.help`
        # to allow help texts to be general objects, not just strings.
        # Used to implement translatable strings, as objects that
        # stringify to the translation.
        if self.short_help:  # pragma: no cover [external-api]
            text = inspect.cleandoc(self._text(self.short_help))
        elif self.help:
            text = click.utils.make_default_short_help(
                self._text(self.help), limit
            )
        else:  # pragma: no cover [external-api]
            text = ''
        if self.deprecated:  # pragma: no cover [external-api]
            # Modification against click 8.1: The translated string is
            # looked up in the derivepassphrase message domain, not the
            # gettext default domain.
            text = str(
                _msg.TranslatedString(_msg.Label.DEPRECATED_COMMAND_LABEL)
            ).format(text=text)
        return text.strip()

    # This method is based on click 8.1; see the comment above the class
    # declaration for license details.
    def format_help_text(
        self,
        ctx: click.Context,
        formatter: click.HelpFormatter,
    ) -> None:
        """Format the help text prologue, if any.

        Args:
            ctx:
                The click context.
            formatter:
                The formatter for the `--help` listing.

        """
        del ctx
        # Modification against click 8.1: Call `_text()` on `self.help`
        # to allow help texts to be general objects, not just strings.
        # Used to implement translatable strings, as objects that
        # stringify to the translation.
        text = (
            inspect.cleandoc(self._text(self.help).partition('\f')[0])
            if self.help is not None
            else ''
        )
        if self.deprecated:  # pragma: no cover [external-api]
            # Modification against click 8.1: The translated string is
            # looked up in the derivepassphrase message domain, not the
            # gettext default domain.
            text = str(
                _msg.TranslatedString(_msg.Label.DEPRECATED_COMMAND_LABEL)
            ).format(text=text)
        if text:  # pragma: no branch
            formatter.write_paragraph()
            with formatter.indentation():
                formatter.write_text(text)

    # This method is based on click 8.1; see the comment above the class
    # declaration for license details.  Consider the whole section
    # marked as modified; the code modifications are too numerous to
    # mark individually.
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

        We unconditionally call [`format_commands`][], and rely on it to
        act as a no-op if we aren't actually a [`click.MultiCommand`][].

        Args:
            ctx:
                The click context.
            formatter:
                The formatter for the `--help` listing.

        """
        default_group_name = ''
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
                rec = (rec[0], self._text(rec[1]))
                if isinstance(param, OptionGroupOption):
                    group_name = self._text(param.option_group_name)
                    epilogs.setdefault(group_name, self._text(param.epilog))
                else:  # pragma: no cover [external-api]
                    group_name = default_group_name
                help_records.setdefault(group_name, []).append(rec)
        if default_group_name in help_records:  # pragma: no branch
            default_group = help_records.pop(default_group_name)
            default_group_label = (
                _msg.Label.OTHER_OPTIONS_LABEL
                if len(default_group) > 1
                else _msg.Label.OPTIONS_LABEL
            )
            default_group_name = self._text(
                _msg.TranslatedString(default_group_label)
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
        self.format_commands(ctx, formatter)

    # This method is based on click 8.1; see the comment above the class
    # declaration for license details.  Consider the whole section
    # marked as modified; the code modifications are too numerous to
    # mark individually.
    def format_commands(
        self,
        ctx: click.Context,
        formatter: click.HelpFormatter,
    ) -> None:
        """Format the subcommands, if any.

        If called on a command object that isn't derived from
        [`click.Group`][], then do nothing.

        Args:
            ctx:
                The click context.
            formatter:
                The formatter for the `--help` listing.

        """
        if not isinstance(self, click.Group):
            return
        commands: list[tuple[str, click.Command]] = []
        for subcommand in self.list_commands(ctx):
            cmd = self.get_command(ctx, subcommand)
            if cmd is None or cmd.hidden:  # pragma: no cover [external-api]
                continue
            commands.append((subcommand, cmd))
        if commands:  # pragma: no branch
            longest_command = max((cmd[0] for cmd in commands), key=len)
            limit = formatter.width - 6 - len(longest_command)
            rows: list[tuple[str, str]] = []
            for subcommand, cmd in commands:
                help_str = self._text(cmd.get_short_help_str(limit) or '')
                rows.append((subcommand, help_str))
            if rows:  # pragma: no branch
                commands_label = self._text(
                    _msg.TranslatedString(_msg.Label.COMMANDS_LABEL)
                )
                with formatter.section(commands_label):
                    formatter.write_dl(rows)

    # This method is based on click 8.1; see the comment above the class
    # declaration for license details.
    def format_epilog(
        self,
        ctx: click.Context,
        formatter: click.HelpFormatter,
    ) -> None:
        """Format the epilog, if any.

        Args:
            ctx:
                The click context.
            formatter:
                The formatter for the `--help` listing.

        """
        del ctx
        if self.epilog:  # pragma: no branch
            # Modification against click 8.1: Call `str()` on
            # `self.epilog` to allow help texts to be general objects,
            # not just strings.  Used to implement translatable strings,
            # as objects that stringify to the translation.
            epilog = inspect.cleandoc(self._text(self.epilog))
            formatter.write_paragraph()
            with formatter.indentation():
                formatter.write_text(epilog)


# Portions of this class are based directly on code from click 8.1.
# (This does not in general include docstrings, unless otherwise noted.)
# They are subject to the 3-clause BSD license in the following
# paragraphs.  Modifications to their code are marked with respective
# comments; they too are released under the same license below.  The
# original code did not contain any "noqa" or "pragma" comments.
#
#     Copyright 2024 Pallets
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the
#     following conditions are met:
#
#      1. Redistributions of source code must retain the above
#         copyright notice, this list of conditions and the
#         following disclaimer.
#
#      2. Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the
#         following disclaimer in the documentation and/or other
#         materials provided with the distribution.
#
#      3. Neither the name of the copyright holder nor the names
#         of its contributors may be used to endorse or promote
#         products derived from this software without specific
#         prior written permission.
#
#     THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
#     CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
#     INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#     MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#     DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
#     CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#     SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
#     NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#     LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#     HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#     CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#     OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#     SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# TODO(the-13th-letter): Remove this class and license block in v1.0.
# https://the13thletter.info/derivepassphrase/latest/upgrade-notes/#v1.0-implied-subcommands
class DefaultToVaultGroup(CommandWithHelpGroups, click.Group):
    """A helper class to implement the default-to-"vault"-subcommand behavior.

    Modifies internal [`click.MultiCommand`][] methods, and thus is both
    an implementation detail and a kludge.

    """

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        """Resolve a command, defaulting to "vault" instead of erroring out."""  # noqa: DOC201
        cmd_name = click.utils.make_str(args[0])

        # Get the command
        cmd = self.get_command(ctx, cmd_name)

        # If we can't find the command but there is a normalization
        # function available, we try with that one.
        if (  # pragma: no cover [external-api]
            cmd is None and ctx.token_normalize_func is not None
        ):
            cmd_name = ctx.token_normalize_func(cmd_name)
            cmd = self.get_command(ctx, cmd_name)

        # If we don't find the command we want to show an error message
        # to the user that it was not provided.  However, there is
        # something else we should do: if the first argument looks like
        # an option we want to kick off parsing again for arguments to
        # resolve things like --help which now should go to the main
        # place.
        if cmd is None and not ctx.resilient_parsing:
            ####
            # BEGIN modifications for derivepassphrase
            #
            # Instead of using
            #
            #     if click.parsers.split_opt(cmd_name)[0]
            #
            # which splits the option prefix (typically `-` or `--`) from
            # the option name, but triggers deprecation warnings in click
            # 8.2.0 and later, we check directly for a `-` prefix.
            #
            # END modifications for derivepassphrase
            ####
            if cmd_name.startswith('-'):
                self.parse_args(ctx, ctx.args)
            ####
            # BEGIN modifications for derivepassphrase
            #
            # Instead of calling ctx.fail here, default to "vault", and
            # issue a deprecation warning.
            deprecation = logging.getLogger(f'{PROG_NAME}.deprecation')
            deprecation.warning(
                _msg.TranslatedString(
                    _msg.WarnMsgTemplate.V10_SUBCOMMAND_REQUIRED
                )
            )
            cmd_name = 'vault'
            cmd = self.get_command(ctx, cmd_name)
            assert cmd is not None, 'Mandatory subcommand "vault" missing!'
            args = [cmd_name, *args]
            #
            # END modifications for derivepassphrase
            ####
        return cmd_name if cmd else None, cmd, args[1:]


# TODO(the-13th-letter): Base this class on CommandWithHelpGroups and
# click.Group in v1.0.
# https://the13thletter.info/derivepassphrase/latest/upgrade-notes/#v1.0-implied-subcommands
class TopLevelCLIEntryPoint(DefaultToVaultGroup):
    """A minor variation of DefaultToVaultGroup for the top-level command.

    When called as a function, this sets up the environment properly
    before invoking the actual callbacks.  Currently, this means setting
    up the logging subsystem and the delegation of Python warnings to
    the logging subsystem.

    The environment setup can be bypassed by calling the `.main` method
    directly.

    """

    def __call__(  # pragma: no cover [external-api]
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


# Actual option groups and callbacks used by derivepassphrase
# ===========================================================


def color_forcing_callback(
    ctx: click.Context,
    param: click.Parameter,
    value: Any,  # noqa: ANN401
) -> None:
    """Disable automatic color (and text highlighting).

    Ideally, we would default to color and text styling if outputting to
    a TTY, or monochrome/unstyled otherwise. We would also support the
    `NO_COLOR` and `FORCE_COLOR` environment variables to override this
    auto-detection, and perhaps the `TTY_COMPATIBLE` variable too.

    Alas, this is not sensible to support at the moment, because the
    conventions are still in flux. And settling on a specific
    interpretation of the conventions would likely prove very difficult
    to change later on in a backward-compatible way. We thus opt for
    a conservative approach and use device-indepedendent text output
    without any color or text styling whatsoever.

    """
    del param, value
    ctx.color = False


def validate_occurrence_constraint(
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
        except ValueError as exc:
            raise click.BadParameter(NOT_AN_INTEGER) from exc
    if int_value < 0:
        raise click.BadParameter(NOT_A_NONNEGATIVE_INTEGER)
    return int_value


def validate_length(
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
        except ValueError as exc:
            raise click.BadParameter(NOT_AN_INTEGER) from exc
    if int_value < 1:
        raise click.BadParameter(NOT_A_POSITIVE_INTEGER)
    return int_value


def common_version_output(
    ctx: click.Context,
    param: click.Parameter,
    value: bool,  # noqa: FBT001
) -> None:
    del param, value
    major_dependencies: list[str] = []
    try:
        cryptography_version = importlib.metadata.version('cryptography')
    except ModuleNotFoundError:
        pass
    else:
        major_dependencies.append(f'cryptography {cryptography_version}')
    major_dependencies.append(f'click {importlib.metadata.version("click")}')

    click.echo(
        ' '.join([
            click.style(PROG_NAME, bold=True),
            VERSION,
        ]),
        color=ctx.color,
    )
    for dependency in major_dependencies:
        click.echo(
            str(
                _msg.TranslatedString(
                    _msg.Label.VERSION_INFO_MAJOR_LIBRARY_TEXT,
                    dependency_name_and_version=dependency,
                )
            ),
            color=ctx.color,
        )


def print_version_info_types(
    version_info_types: dict[_msg.Label, list[str]],
    /,
    *,
    ctx: click.Context,
) -> None:
    for message_label, item_list in version_info_types.items():
        if item_list:
            current_length = len(str(_msg.TranslatedString(message_label)))
            formatted_item_list_pieces: list[str] = []
            n = len(item_list)
            for i, item in enumerate(item_list, start=1):
                space = ' '
                punctuation = '.' if i == n else ','
                if (
                    current_length + len(space) + len(item) + len(punctuation)
                    <= VERSION_OUTPUT_WRAPPING_WIDTH
                ):
                    current_length += len(space) + len(item) + len(punctuation)
                    piece = f'{space}{item}{punctuation}'
                else:
                    space = '    '
                    current_length = len(space) + len(item) + len(punctuation)
                    piece = f'\n{space}{item}{punctuation}'
                formatted_item_list_pieces.append(piece)
            click.echo(
                ''.join([
                    click.style(
                        str(_msg.TranslatedString(message_label)),
                        bold=True,
                    ),
                    ''.join(formatted_item_list_pieces),
                ]),
                color=ctx.color,
            )


def derivepassphrase_version_option_callback(
    ctx: click.Context,
    param: click.Parameter,
    value: bool,  # noqa: FBT001
) -> None:
    if value and not ctx.resilient_parsing:
        common_version_output(ctx, param, value)
        derivation_schemes = dict.fromkeys(_types.DerivationScheme, True)
        supported_subcommands = set(_types.Subcommand)
        click.echo()
        version_info_types: dict[_msg.Label, list[str]] = {
            _msg.Label.SUPPORTED_DERIVATION_SCHEMES: [
                k for k, v in derivation_schemes.items() if v
            ],
            _msg.Label.UNAVAILABLE_DERIVATION_SCHEMES: [
                k for k, v in derivation_schemes.items() if not v
            ],
            _msg.Label.SUPPORTED_SUBCOMMANDS: sorted(supported_subcommands),
        }
        print_version_info_types(version_info_types, ctx=ctx)
        ctx.exit()


def export_version_option_callback(
    ctx: click.Context,
    param: click.Parameter,
    value: bool,  # noqa: FBT001
) -> None:
    if value and not ctx.resilient_parsing:
        common_version_output(ctx, param, value)
        supported_subcommands = set(_types.ExportSubcommand)
        foreign_configuration_formats = {
            _types.ForeignConfigurationFormat.VAULT_STOREROOM: False,
            _types.ForeignConfigurationFormat.VAULT_V02: False,
            _types.ForeignConfigurationFormat.VAULT_V03: False,
        }
        click.echo()
        version_info_types: dict[_msg.Label, list[str]] = {
            _msg.Label.UNAVAILABLE_FOREIGN_CONFIGURATION_FORMATS: [
                k for k, v in foreign_configuration_formats.items() if not v
            ],
            _msg.Label.SUPPORTED_SUBCOMMANDS: sorted(supported_subcommands),
        }
        print_version_info_types(version_info_types, ctx=ctx)
        ctx.exit()


def export_vault_version_option_callback(
    ctx: click.Context,
    param: click.Parameter,
    value: bool,  # noqa: FBT001
) -> None:
    if value and not ctx.resilient_parsing:
        common_version_output(ctx, param, value)
        foreign_configuration_formats = {
            _types.ForeignConfigurationFormat.VAULT_STOREROOM: False,
            _types.ForeignConfigurationFormat.VAULT_V02: False,
            _types.ForeignConfigurationFormat.VAULT_V03: False,
        }
        known_extras = {
            _types.PEP508Extra.EXPORT: False,
        }
        from derivepassphrase.exporter import storeroom, vault_native  # noqa: I001,PLC0415

        foreign_configuration_formats[
            _types.ForeignConfigurationFormat.VAULT_STOREROOM
        ] = not storeroom.STUBBED
        foreign_configuration_formats[
            _types.ForeignConfigurationFormat.VAULT_V02
        ] = not vault_native.STUBBED
        foreign_configuration_formats[
            _types.ForeignConfigurationFormat.VAULT_V03
        ] = not vault_native.STUBBED
        known_extras[_types.PEP508Extra.EXPORT] = (
            not storeroom.STUBBED and not vault_native.STUBBED
        )
        click.echo()
        version_info_types: dict[_msg.Label, list[str]] = {
            _msg.Label.SUPPORTED_FOREIGN_CONFIGURATION_FORMATS: [
                k for k, v in foreign_configuration_formats.items() if v
            ],
            _msg.Label.UNAVAILABLE_FOREIGN_CONFIGURATION_FORMATS: [
                k for k, v in foreign_configuration_formats.items() if not v
            ],
            _msg.Label.ENABLED_PEP508_EXTRAS: [
                k for k, v in known_extras.items() if v
            ],
        }
        print_version_info_types(version_info_types, ctx=ctx)
        ctx.exit()


def vault_version_option_callback(
    ctx: click.Context,
    param: click.Parameter,
    value: bool,  # noqa: FBT001
) -> None:
    if value and not ctx.resilient_parsing:
        common_version_output(ctx, param, value)
        features = {
            _types.Feature.SSH_KEY: hasattr(socket, 'AF_UNIX'),
        }
        click.echo()
        version_info_types: dict[_msg.Label, list[str]] = {
            _msg.Label.SUPPORTED_FEATURES: [
                k for k, v in features.items() if v
            ],
            _msg.Label.UNAVAILABLE_FEATURES: [
                k for k, v in features.items() if not v
            ],
        }
        print_version_info_types(version_info_types, ctx=ctx)
        ctx.exit()


def version_option(
    version_option_callback: Callable[
        [click.Context, click.Parameter, Any], Any
    ],
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    return click.option(
        '--version',
        is_flag=True,
        is_eager=True,
        expose_value=False,
        callback=version_option_callback,
        cls=StandardOption,
        help=_msg.TranslatedString(_msg.Label.VERSION_OPTION_HELP_TEXT),
    )


color_forcing_pseudo_option = click.option(
    '--_pseudo-option-color-forcing',
    '_color_forcing',
    is_flag=True,
    is_eager=True,
    expose_value=False,
    hidden=True,
    callback=color_forcing_callback,
    help='(pseudo-option)',
)


class PassphraseGenerationOption(OptionGroupOption):
    """Passphrase generation options for the CLI."""

    option_group_name = _msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_LABEL
    )
    epilog = _msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_EPILOG,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    )


class ConfigurationOption(OptionGroupOption):
    """Configuration options for the CLI."""

    option_group_name = _msg.TranslatedString(_msg.Label.CONFIGURATION_LABEL)
    epilog = _msg.TranslatedString(_msg.Label.CONFIGURATION_EPILOG)


class StorageManagementOption(OptionGroupOption):
    """Storage management options for the CLI."""

    option_group_name = _msg.TranslatedString(
        _msg.Label.STORAGE_MANAGEMENT_LABEL
    )
    epilog = _msg.TranslatedString(
        _msg.Label.STORAGE_MANAGEMENT_EPILOG,
        metavar=_msg.TranslatedString(
            _msg.Label.STORAGE_MANAGEMENT_METAVAR_PATH
        ),
    )


class CompatibilityOption(OptionGroupOption):
    """Compatibility and incompatibility options for the CLI."""

    option_group_name = _msg.TranslatedString(
        _msg.Label.COMPATIBILITY_OPTION_LABEL
    )


class LoggingOption(OptionGroupOption):
    """Logging options for the CLI."""

    option_group_name = _msg.TranslatedString(_msg.Label.LOGGING_LABEL)
    epilog = ''


debug_option = click.option(
    '--debug',
    'logging_level',
    is_flag=True,
    flag_value=logging.DEBUG,
    expose_value=False,
    callback=adjust_logging_level,
    help=_msg.TranslatedString(_msg.Label.DEBUG_OPTION_HELP_TEXT),
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
    help=_msg.TranslatedString(_msg.Label.VERBOSE_OPTION_HELP_TEXT),
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
    help=_msg.TranslatedString(_msg.Label.QUIET_OPTION_HELP_TEXT),
    cls=LoggingOption,
)


def standard_logging_options(f: Callable[P, R]) -> Callable[P, R]:
    """Decorate the function with standard logging click options.

    Adds the three click options `-v`/`--verbose`, `-q`/`--quiet` and
    `--debug`, which calls back into the [`adjust_logging_level`][]
    function (with different argument values).

    Args:
        f: A callable to decorate.

    Returns:
        The decorated callable.

    """
    return debug_option(verbose_option(quiet_option(f)))


# Shell completion
# ================


# TODO(the-13th-letter): Remove this once upstream click's Zsh completion
# script properly supports colons.
#
# https://github.com/pallets/click/pull/2846
class ZshComplete(click.shell_completion.ZshComplete):
    """Zsh completion class that supports colons.

    `click`'s Zsh completion class (at least v8.1.7 and v8.1.8) uses
    some completion helper functions (provided by Zsh) that parse each
    completion item into value-description pairs, separated by a colon.
    Other completion helper functions don't.  Correspondingly, any
    internal colons in the completion item's value sometimes need to be
    escaped, and sometimes don't.

    The "right" way to fix this is to modify the Zsh completion script
    to only use one type of serialization: either escaped, or unescaped.
    However, the Zsh completion script itself may already be installed
    in the user's Zsh settings, and we have no way of knowing that.
    Therefore, it is better to change the `format_completion` method to
    adaptively and "smartly" emit colon-escaped output or not, based on
    whether the completion script will be using it.

    """

    @override
    def format_completion(
        self,
        item: click.shell_completion.CompletionItem,
    ) -> str:
        """Return a suitable serialization of the CompletionItem.

        This serialization ensures colons in the item value are properly
        escaped if and only if the completion script will attempt to
        pass a colon-separated key/description pair to the underlying
        Zsh machinery.  This is the case if and only if the help text is
        non-degenerate.

        """
        help_ = item.help or '_'
        value = item.value.replace(':', r'\:' if help_ != '_' else ':')
        return f'{item.type}\n{value}\n{help_}'


# Our ZshComplete class depends crucially on the exact shape of the Zsh
# completion script.  So only fix the completion formatter if the
# completion script is still the same.
#
# (This Zsh script is part of click, and available under the
# 3-clause-BSD license.)
_ORIG_SOURCE_TEMPLATE = """\
#compdef %(prog_name)s

%(complete_func)s() {
    local -a completions
    local -a completions_with_descriptions
    local -a response
    (( ! $+commands[%(prog_name)s] )) && return 1

    response=("${(@f)$(env COMP_WORDS="${words[*]}" COMP_CWORD=$((CURRENT-1)) \
%(complete_var)s=zsh_complete %(prog_name)s)}")

    for type key descr in ${response}; do
        if [[ "$type" == "plain" ]]; then
            if [[ "$descr" == "_" ]]; then
                completions+=("$key")
            else
                completions_with_descriptions+=("$key":"$descr")
            fi
        elif [[ "$type" == "dir" ]]; then
            _path_files -/
        elif [[ "$type" == "file" ]]; then
            _path_files -f
        fi
    done

    if [ -n "$completions_with_descriptions" ]; then
        _describe -V unsorted completions_with_descriptions -U
    fi

    if [ -n "$completions" ]; then
        compadd -U -V unsorted -a completions
    fi
}

if [[ $zsh_eval_context[-1] == loadautofunc ]]; then
    # autoload from fpath, call function directly
    %(complete_func)s "$@"
else
    # eval/source/. command, register function for later
    compdef %(complete_func)s %(prog_name)s
fi
"""
if (
    click.shell_completion.ZshComplete.source_template == _ORIG_SOURCE_TEMPLATE
):  # pragma: no cover [external]
    click.shell_completion.add_completion_class(ZshComplete)
