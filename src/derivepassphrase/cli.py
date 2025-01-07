# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

# ruff: noqa: TRY400

"""Command-line interface for derivepassphrase."""

from __future__ import annotations

import base64
import collections
import copy
import enum
import functools
import importlib
import inspect
import json
import logging
import os
import shlex
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
import click.shell_completion
from typing_extensions import (
    Any,
    ParamSpec,
    Self,
    assert_never,
    override,
)

import derivepassphrase as dpp
from derivepassphrase import _cli_msg as _msg
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

PROG_NAME = _msg.PROG_NAME
KEY_DISPLAY_LENGTH = 50

# Error messages
_INVALID_VAULT_CONFIG = 'Invalid vault config'
_AGENT_COMMUNICATION_ERROR = 'Error communicating with the SSH agent'
_NO_SUITABLE_KEYS = 'No suitable SSH keys were found'
_EMPTY_SELECTION = 'Empty selection'
_NOT_AN_INTEGER = 'not an integer'
_NOT_A_NONNEGATIVE_INTEGER = 'not a non-negative integer'
_NOT_A_POSITIVE_INTEGER = 'not a positive integer'


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

    def collect_usage_pieces(self, ctx: click.Context) -> list[str]:
        """Return the pieces for the usage string.

        Based on code from click 8.1.  Subject to the following license
        (3-clause BSD license):

            Copyright 2024 Pallets

            Redistribution and use in source and binary forms, with or
            without modification, are permitted provided that the
            following conditions are met:

             1. Redistributions of source code must retain the above
                copyright notice, this list of conditions and the
                following disclaimer.

             2. Redistributions in binary form must reproduce the above
                copyright notice, this list of conditions and the
                following disclaimer in the documentation and/or other
                materials provided with the distribution.

             3. Neither the name of the copyright holder nor the names
                of its contributors may be used to endorse or promote
                products derived from this software without specific
                prior written permission.

            THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
            CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
            INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
            MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
            DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
            CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
            SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
            NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
            LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
            HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
            CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
            OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
            SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

        Modifications are marked with respective comments.  They too are
        released under the same license above.  The original code did
        not contain any "noqa" or "pragma" comments.

        Args:
            ctx:
                The click context.

        """
        rv = [str(self.options_metavar)] if self.options_metavar else []
        for param in self.get_params(ctx):
            rv.extend(str(x) for x in param.get_usage_pieces(ctx))
        return rv

    def get_help_option(
        self,
        ctx: click.Context,
    ) -> click.Option | None:
        """Return a standard help option object.

        Based on code from click 8.1.  Subject to the following license
        (3-clause BSD license):

            Copyright 2024 Pallets

            Redistribution and use in source and binary forms, with or
            without modification, are permitted provided that the
            following conditions are met:

             1. Redistributions of source code must retain the above
                copyright notice, this list of conditions and the
                following disclaimer.

             2. Redistributions in binary form must reproduce the above
                copyright notice, this list of conditions and the
                following disclaimer in the documentation and/or other
                materials provided with the distribution.

             3. Neither the name of the copyright holder nor the names
                of its contributors may be used to endorse or promote
                products derived from this software without specific
                prior written permission.

            THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
            CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
            INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
            MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
            DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
            CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
            SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
            NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
            LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
            HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
            CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
            OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
            SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

        Modifications are marked with respective comments.  They too are
        released under the same license above.  The original code did
        not contain any "noqa" or "pragma" comments.

        Args:
            ctx:
                The click context.

        """
        help_options = self.get_help_option_names(ctx)

        if not help_options or not self.add_help_option:  # pragma: no cover
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

    def get_short_help_str(
        self,
        limit: int = 45,
    ) -> str:
        """Return the short help string for a command.

        If only a long help string is given, shorten it.

        Based on code from click 8.1.  Subject to the following license
        (3-clause BSD license):

            Copyright 2024 Pallets

            Redistribution and use in source and binary forms, with or
            without modification, are permitted provided that the
            following conditions are met:

             1. Redistributions of source code must retain the above
                copyright notice, this list of conditions and the
                following disclaimer.

             2. Redistributions in binary form must reproduce the above
                copyright notice, this list of conditions and the
                following disclaimer in the documentation and/or other
                materials provided with the distribution.

             3. Neither the name of the copyright holder nor the names
                of its contributors may be used to endorse or promote
                products derived from this software without specific
                prior written permission.

            THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
            CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
            INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
            MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
            DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
            CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
            SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
            NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
            LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
            HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
            CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
            OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
            SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

        Modifications are marked with respective comments.  They too are
        released under the same license above.  The original code did
        not contain any "noqa" or "pragma" comments.

        Args:
            limit:
                The maximum width of the short help string.

        """
        # Modification against click 8.1: Call `_text()` on `self.help`
        # to allow help texts to be general objects, not just strings.
        # Used to implement translatable strings, as objects that
        # stringify to the translation.
        if self.short_help:  # pragma: no cover
            text = inspect.cleandoc(self._text(self.short_help))
        elif self.help:
            text = click.utils.make_default_short_help(
                self._text(self.help), limit
            )
        else:  # pragma: no cover
            text = ''
        if self.deprecated:  # pragma: no cover
            # Modification against click 8.1: The translated string is
            # looked up in the derivepassphrase message domain, not the
            # gettext default domain.
            text = str(
                _msg.TranslatedString(_msg.Label.DEPRECATED_COMMAND_LABEL)
            ).format(text=text)
        return text.strip()

    def format_help_text(
        self,
        ctx: click.Context,
        formatter: click.HelpFormatter,
    ) -> None:
        """Format the help text prologue, if any.

        Based on code from click 8.1.  Subject to the following license
        (3-clause BSD license):

            Copyright 2024 Pallets

            Redistribution and use in source and binary forms, with or
            without modification, are permitted provided that the
            following conditions are met:

             1. Redistributions of source code must retain the above
                copyright notice, this list of conditions and the
                following disclaimer.

             2. Redistributions in binary form must reproduce the above
                copyright notice, this list of conditions and the
                following disclaimer in the documentation and/or other
                materials provided with the distribution.

             3. Neither the name of the copyright holder nor the names
                of its contributors may be used to endorse or promote
                products derived from this software without specific
                prior written permission.

            THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
            CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
            INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
            MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
            DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
            CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
            SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
            NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
            LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
            HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
            CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
            OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
            SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

        Modifications are marked with respective comments.  They too are
        released under the same license above.  The original code did
        not contain any "noqa" or "pragma" comments.

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
        if self.deprecated:  # pragma: no cover
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

        Based on code from click 8.1.  Subject to the following license
        (3-clause BSD license):

            Copyright 2024 Pallets

            Redistribution and use in source and binary forms, with or
            without modification, are permitted provided that the
            following conditions are met:

             1. Redistributions of source code must retain the above
                copyright notice, this list of conditions and the
                following disclaimer.

             2. Redistributions in binary form must reproduce the above
                copyright notice, this list of conditions and the
                following disclaimer in the documentation and/or other
                materials provided with the distribution.

             3. Neither the name of the copyright holder nor the names
                of its contributors may be used to endorse or promote
                products derived from this software without specific
                prior written permission.

            THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
            CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
            INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
            MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
            DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
            CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
            SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
            NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
            LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
            HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
            CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
            OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
            SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

        Modifications are released under the same license above.

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
                else:  # pragma: no cover
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

    def format_commands(
        self,
        ctx: click.Context,
        formatter: click.HelpFormatter,
    ) -> None:
        """Format the subcommands, if any.

        If called on a command object that isn't derived from
        [`click.MultiCommand`][], then do nothing.

        Based on code from click 8.1.  Subject to the following license
        (3-clause BSD license):

            Copyright 2024 Pallets

            Redistribution and use in source and binary forms, with or
            without modification, are permitted provided that the
            following conditions are met:

             1. Redistributions of source code must retain the above
                copyright notice, this list of conditions and the
                following disclaimer.

             2. Redistributions in binary form must reproduce the above
                copyright notice, this list of conditions and the
                following disclaimer in the documentation and/or other
                materials provided with the distribution.

             3. Neither the name of the copyright holder nor the names
                of its contributors may be used to endorse or promote
                products derived from this software without specific
                prior written permission.

            THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
            CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
            INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
            MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
            DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
            CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
            SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
            NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
            LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
            HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
            CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
            OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
            SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

        Modifications are marked with respective comments.  They too are
        released under the same license above.  The original code did
        not contain any "noqa" or "pragma" comments.

        Args:
            ctx:
                The click context.
            formatter:
                The formatter for the `--help` listing.

        """
        if not isinstance(self, click.MultiCommand):
            return
        commands: list[tuple[str, click.Command]] = []
        for subcommand in self.list_commands(ctx):
            cmd = self.get_command(ctx, subcommand)
            if cmd is None or cmd.hidden:  # pragma: no cover
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

    def format_epilog(
        self,
        ctx: click.Context,
        formatter: click.HelpFormatter,
    ) -> None:
        """Format the epilog, if any.

        Based on code from click 8.1.  Subject to the following license
        (3-clause BSD license):

            Copyright 2024 Pallets

            Redistribution and use in source and binary forms, with or
            without modification, are permitted provided that the
            following conditions are met:

             1. Redistributions of source code must retain the above
                copyright notice, this list of conditions and the
                following disclaimer.

             2. Redistributions in binary form must reproduce the above
                copyright notice, this list of conditions and the
                following disclaimer in the documentation and/or other
                materials provided with the distribution.

             3. Neither the name of the copyright holder nor the names
                of its contributors may be used to endorse or promote
                products derived from this software without specific
                prior written permission.

            THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
            CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
            INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
            MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
            DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
            CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
            SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
            NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
            LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
            HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
            CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
            OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
            SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

        Modifications are marked with respective comments.  They too are
        released under the same license above.

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


def version_option_callback(
    ctx: click.Context,
    param: click.Parameter,
    value: bool,  # noqa: FBT001
) -> None:
    del param
    if value and not ctx.resilient_parsing:
        click.echo(
            str(
                _msg.TranslatedString(
                    _msg.Label.VERSION_INFO_TEXT,
                    PROG_NAME=PROG_NAME,
                    __version__=__version__,
                )
            ),
        )
        ctx.exit()


def version_option(f: Callable[P, R]) -> Callable[P, R]:
    return click.option(
        '--version',
        is_flag=True,
        is_eager=True,
        expose_value=False,
        callback=version_option_callback,
        cls=StandardOption,
        help=_msg.TranslatedString(_msg.Label.VERSION_OPTION_HELP_TEXT),
    )(f)


def color_forcing_callback(
    ctx: click.Context,
    param: click.Parameter,
    value: Any,  # noqa: ANN401
) -> None:
    """Force the `click` context to honor `NO_COLOR` and `FORCE_COLOR`."""
    del param, value
    if os.environ.get('NO_COLOR'):
        ctx.color = False
    if os.environ.get('FORCE_COLOR'):
        ctx.color = True


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

# Use naive filename completion for the `path` argument of
# `derivepassphrase vault`'s `--import` and `--export` options, as well
# as the `path` argument of `derivepassphrase export vault`.  The latter
# treats the pseudo-filename `VAULT_PATH` specially, but this is awkward
# to combine with standard filename completion, particularly in bash, so
# we would probably have to implement *all* completion (`VAULT_PATH` and
# filename completion) ourselves, lacking some niceties of bash's
# built-in completion (e.g., adding spaces or slashes depending on
# whether the completion is a directory or a complete filename).


def _shell_complete_path(
    ctx: click.Context,
    parameter: click.Parameter,
    value: str,
) -> list[str | click.shell_completion.CompletionItem]:
    """Request standard path completion for the `path` argument."""  # noqa: DOC201
    del ctx, parameter, value
    return [click.shell_completion.CompletionItem('', type='file')]


# The standard `click` shell completion scripts serialize the completion
# items as newline-separated one-line entries, which get silently
# corrupted if the value contains newlines.  Each shell imposes
# additional restrictions: Fish uses newlines in all internal completion
# helper scripts, so it is difficult, if not impossible, to register
# completion entries containing newlines if completion comes from within
# a Fish completion function (instead of a Fish builtin).  Zsh's
# completion system supports descriptions for each completion item, and
# the completion helper functions parse every entry as a colon-separated
# 2-tuple of item and description, meaning any colon in the item value
# must be escaped.  Finally, Bash requires the result array to be
# populated at the completion function's top-level scope, but for/while
# loops within pipelines do not run at top-level scope, and Bash *also*
# strips NUL characters from command substitution output, making it
# difficult to read in external data into an array in a cross-platform
# manner from entirely within Bash.
#
# We capitulate in front of these problems---most egregiously because of
# Fish---and ensure that completion items (in this case: service names)
# never contain ASCII control characters by refusing to offer such
# items as valid completions.  On the other side, `derivepassphrase`
# will warn the user when configuring or importing a service with such
# a name that it will not be available for shell completion.


def _is_completable_item(obj: object) -> bool:
    """Return whether the item is completable on the command-line.

    The item is completable if and only if it contains no ASCII control
    characters (U+0000 through U+001F, and U+007F).

    """
    obj = str(obj)
    forbidden = frozenset(chr(i) for i in range(32)) | {'\x7f'}
    return not any(f in obj for f in forbidden)


def _shell_complete_service(
    ctx: click.Context,
    parameter: click.Parameter,
    value: str,
) -> list[str | click.shell_completion.CompletionItem]:
    """Return known vault service names as completion items.

    Service names are looked up in the vault configuration file.  All
    errors will be suppressed.  Additionally, any service names deemed
    not completable as per [`_is_completable_item`][] will be silently
    skipped.

    """
    del ctx, parameter
    try:
        config = _load_config()
        return sorted(
            sv
            for sv in config['services']
            if sv.startswith(value) and _is_completable_item(sv)
        )
    except FileNotFoundError:
        try:
            config, _exc = _migrate_and_load_old_config()
            return sorted(
                sv
                for sv in config['services']
                if sv.startswith(value) and _is_completable_item(sv)
            )
        except FileNotFoundError:
            return []
    except Exception:  # noqa: BLE001
        return []


class ZshComplete(click.shell_completion.ZshComplete):
    """Zsh completion class that supports colons.

    `click`'s Zsh completion class (at least v8.1.7 and v8.1.8) uses
    completion helper functions (provided by Zsh) that parse each
    completion item into value-description pairs, separated by a colon.
    Correspondingly, any internal colons in the completion item's value
    need to be escaped.  `click` doesn't do this.  So, this subclass
    overrides those parts, and adds the missing escaping.

    """

    @override
    def format_completion(
        self,
        item: click.shell_completion.CompletionItem,
    ) -> str:
        """Return a suitable serialization of the CompletionItem.

        This serialization ensures colons in the item value are properly
        escaped.

        """
        type, value, help = (  # noqa: A001
            item.type,
            item.value.replace(':', '\\:'),
            item.help or '_',
        )
        return f'{type}\n{value}\n{help}'


click.shell_completion.add_completion_class(ZshComplete)


# Top-level
# =========


class _DefaultToVaultGroup(CommandWithHelpGroups, click.Group):
    """A helper class to implement the default-to-"vault"-subcommand behavior.

    Modifies internal [`click.MultiCommand`][] methods, and thus is both
    an implementation detail and a kludge.

    """

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        """Resolve a command, but default to "vault" instead of erroring out.

        Based on code from click 8.1, which appears to be essentially
        untouched since at least click 3.2.  Subject to the following
        license (3-clause BSD license):

            Copyright 2024 Pallets

            Redistribution and use in source and binary forms, with or
            without modification, are permitted provided that the following
            conditions are met:

             1. Redistributions of source code must retain the above
                copyright notice, this list of conditions and the following
                disclaimer.

             2. Redistributions in binary form must reproduce the above
                copyright notice, this list of conditions and the following
                disclaimer in the documentation and/or other materials
                provided with the distribution.

             3. Neither the name of the copyright holder nor the names of
                its contributors may be used to endorse or promote products
                derived from this software without specific prior written
                permission.

            THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
            CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
            INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
            MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
            DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
            CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
            SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
            LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
            USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
            AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
            LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
            IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
            THE POSSIBILITY OF SUCH DAMAGE.

        Modifications to this routine are marked with "modifications for
        derivepassphrase".  Furthermore, all "pragma" and "noqa" comments
        are also modifications for derivepassphrase.

        """  # noqa: DOC201
        cmd_name = click.utils.make_str(args[0])

        # Get the command
        cmd = self.get_command(ctx, cmd_name)

        # If we can't find the command but there is a normalization
        # function available, we try with that one.
        if (  # pragma: no cover
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
            if click.parser.split_opt(cmd_name)[0]:
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
    epilog=_msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_EPILOG_01),
    invoke_without_command=True,
    cls=_TopLevelCLIEntryPoint,
    help=(
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_01),
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_02),
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_03),
    ),
)
@version_option
@color_forcing_pseudo_option
@standard_logging_options
@click.pass_context
def derivepassphrase(ctx: click.Context, /) -> None:
    """Derive a strong passphrase, deterministically, from a master secret.

    This is a [`click`][CLICK]-powered command-line interface function,
    and not intended for programmatic use.  See the derivepassphrase(1)
    manpage for full documentation of the interface.  (See also
    [`click.testing.CliRunner`][] for controlled, programmatic
    invocation.)

    [CLICK]: https://pypi.org/package/click/

    """
    deprecation = logging.getLogger(f'{PROG_NAME}.deprecation')
    if ctx.invoked_subcommand is None:
        deprecation.warning(
            _msg.TranslatedString(
                _msg.WarnMsgTemplate.V10_SUBCOMMAND_REQUIRED
            ),
            extra={'color': ctx.color},
        )
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
    help=(
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_EXPORT_01),
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_EXPORT_02),
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_EXPORT_03),
    ),
)
@version_option
@color_forcing_pseudo_option
@standard_logging_options
@click.pass_context
def derivepassphrase_export(ctx: click.Context, /) -> None:
    """Export a foreign configuration to standard output.

    This is a [`click`][CLICK]-powered command-line interface function,
    and not intended for programmatic use.  See the
    derivepassphrase-export(1) manpage for full documentation of the
    interface.  (See also [`click.testing.CliRunner`][] for controlled,
    programmatic invocation.)

    [CLICK]: https://pypi.org/package/click/

    """
    deprecation = logging.getLogger(f'{PROG_NAME}.deprecation')
    if ctx.invoked_subcommand is None:
        deprecation.warning(
            _msg.TranslatedString(
                _msg.WarnMsgTemplate.V10_SUBCOMMAND_REQUIRED
            ),
            extra={'color': ctx.color},
        )
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
    cls=CommandWithHelpGroups,
    help=(
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_EXPORT_VAULT_01),
        _msg.TranslatedString(
            _msg.Label.DERIVEPASSPHRASE_EXPORT_VAULT_02,
            path_metavar=_msg.TranslatedString(
                _msg.Label.EXPORT_VAULT_METAVAR_PATH,
            ),
        ),
        _msg.TranslatedString(
            _msg.Label.DERIVEPASSPHRASE_EXPORT_VAULT_03,
            path_metavar=_msg.TranslatedString(
                _msg.Label.EXPORT_VAULT_METAVAR_PATH,
            ),
        ),
    ),
)
@click.option(
    '-f',
    '--format',
    'formats',
    metavar=_msg.TranslatedString(_msg.Label.EXPORT_VAULT_FORMAT_METAVAR_FMT),
    multiple=True,
    default=('v0.3', 'v0.2', 'storeroom'),
    type=click.Choice(['v0.2', 'v0.3', 'storeroom']),
    help=_msg.TranslatedString(
        _msg.Label.EXPORT_VAULT_FORMAT_HELP_TEXT,
        defaults_hint=_msg.TranslatedString(
            _msg.Label.EXPORT_VAULT_FORMAT_DEFAULTS_HELP_TEXT,
        ),
        metavar=_msg.TranslatedString(
            _msg.Label.EXPORT_VAULT_FORMAT_METAVAR_FMT,
        ),
    ),
    cls=StandardOption,
)
@click.option(
    '-k',
    '--key',
    metavar=_msg.TranslatedString(_msg.Label.EXPORT_VAULT_KEY_METAVAR_K),
    help=_msg.TranslatedString(
        _msg.Label.EXPORT_VAULT_KEY_HELP_TEXT,
        metavar=_msg.TranslatedString(_msg.Label.EXPORT_VAULT_KEY_METAVAR_K),
        defaults_hint=_msg.TranslatedString(
            _msg.Label.EXPORT_VAULT_KEY_DEFAULTS_HELP_TEXT,
        ),
    ),
    cls=StandardOption,
)
@version_option
@color_forcing_pseudo_option
@standard_logging_options
@click.argument(
    'path',
    metavar=_msg.TranslatedString(_msg.Label.EXPORT_VAULT_METAVAR_PATH),
    required=True,
    shell_complete=_shell_complete_path,
)
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

    This is a [`click`][CLICK]-powered command-line interface function,
    and not intended for programmatic use.  See the
    derivepassphrase-export-vault(1) manpage for full documentation of
    the interface.  (See also [`click.testing.CliRunner`][] for
    controlled, programmatic invocation.)

    [CLICK]: https://pypi.org/package/click/

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
            logger.info(
                _msg.TranslatedString(
                    _msg.InfoMsgTemplate.CANNOT_LOAD_AS_VAULT_CONFIG,
                    path=path,
                    fmt=fmt,
                ),
                extra={'color': ctx.color},
            )
            continue
        except OSError as exc:
            logger.error(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_PARSE_AS_VAULT_CONFIG_OSERROR,
                    path=path,
                    error=exc.strerror,
                    filename=exc.filename,
                ).maybe_without_filename(),
                extra={'color': ctx.color},
            )
            ctx.exit(1)
        except ModuleNotFoundError:
            logger.error(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.MISSING_MODULE,
                    module='cryptography',
                ),
                extra={'color': ctx.color},
            )
            logger.info(
                _msg.TranslatedString(
                    _msg.InfoMsgTemplate.PIP_INSTALL_EXTRA,
                    extra_name='export',
                ),
                extra={'color': ctx.color},
            )
            ctx.exit(1)
        else:
            if not _types.is_vault_config(config):
                logger.error(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.INVALID_VAULT_CONFIG,
                        config=config,
                    ),
                    extra={'color': ctx.color},
                )
                ctx.exit(1)
            click.echo(
                json.dumps(config, indent=2, sort_keys=True),
                color=ctx.color,
            )
            break
    else:
        logger.error(
            _msg.TranslatedString(
                _msg.ErrMsgTemplate.CANNOT_PARSE_AS_VAULT_CONFIG,
                path=path,
            ).maybe_without_filename(),
            extra={'color': ctx.color},
        )
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

    """  # noqa: DOC501
    if not _types.is_vault_config(config):
        raise ValueError(_INVALID_VAULT_CONFIG)
    filename = _config_filename(subsystem='vault')
    filedir = os.path.dirname(os.path.abspath(filename))
    try:
        os.makedirs(filedir, exist_ok=False)
    except FileExistsError:
        if not os.path.isdir(filedir):
            raise
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
        except EOFError as exc:  # pragma: no cover
            raise RuntimeError(_AGENT_COMMUNICATION_ERROR) from exc
        suitable_keys = copy.copy(all_key_comment_pairs)
        for pair in all_key_comment_pairs:
            key, _comment = pair
            if vault.Vault.is_suitable_ssh_key(key, client=client):
                yield pair
    if not suitable_keys:  # pragma: no cover
        raise LookupError(_NO_SUITABLE_KEYS)


def _prompt_for_selection(
    items: Sequence[str | bytes],
    heading: str = 'Possible choices:',
    single_choice_prompt: str = 'Confirm this choice?',
    ctx: click.Context | None = None,
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
        ctx:
            An optional `click` context, from which output device
            properties and color preferences will be queried.

    Returns:
        An index into the items sequence, indicating the user's
        selection.

    Raises:
        IndexError:
            The user made an invalid or empty selection, or requested an
            abort.

    """
    n = len(items)
    color = ctx.color if ctx is not None else None
    if heading:
        click.echo(click.style(heading, bold=True), color=color)
    for i, x in enumerate(items, start=1):
        click.echo(click.style(f'[{i}]', bold=True), nl=False, color=color)
        click.echo(' ', nl=False, color=color)
        click.echo(x, color=color)
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
    conn: ssh_agent.SSHAgentClient | socket.socket | None = None,
    /,
    *,
    ctx: click.Context | None = None,
) -> bytes | bytearray:
    """Interactively select an SSH key for passphrase derivation.

    Suitable SSH keys are queried from the running SSH agent (see
    [`ssh_agent.SSHAgentClient.list_keys`][]), then the user is prompted
    interactively (see [`click.prompt`][]) for a selection.

    Args:
        conn:
            An optional connection hint to the SSH agent.  See
            [`ssh_agent.SSHAgentClient.ensure_agent_subcontext`][].
        ctx:
            An `click` context, queried for output device properties and
            color preferences when issuing the prompt.

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
        ctx=ctx,
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
        'str',
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
    ctx: click.Context | None = None,
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
                    'The %s passphrase is not %s-normalized.  Its '
                    'serialization as a byte string may not be what you '
                    'expect it to be, even if it *displays* correctly.  '
                    'Please make sure to double-check any derived '
                    'passphrases for unexpected results.'
                ),
                formatted_key,
                form,
                stacklevel=2,
                extra={'color': ctx.color if ctx is not None else None},
            )


def _key_to_phrase(
    key_: str | bytes | bytearray,
    /,
    *,
    error_callback: Callable[..., NoReturn] = sys.exit,
) -> bytes | bytearray:
    key = base64.standard_b64decode(key_)
    try:
        with ssh_agent.SSHAgentClient.ensure_agent_subcontext() as client:
            try:
                return vault.Vault.phrase_from_key(key, conn=client)
            except ssh_agent.SSHAgentFailedError as exc:
                try:
                    keylist = client.list_keys()
                except ssh_agent.SSHAgentFailedError:
                    pass
                except Exception as exc2:  # noqa: BLE001
                    exc.__context__ = exc2
                else:
                    if not any(  # pragma: no branch
                        k == key for k, _ in keylist
                    ):
                        error_callback(
                            _msg.TranslatedString(
                                _msg.ErrMsgTemplate.SSH_KEY_NOT_LOADED
                            )
                        )
                error_callback(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.AGENT_REFUSED_SIGNATURE
                    ),
                    exc_info=exc,
                )
    except KeyError:
        error_callback(
            _msg.TranslatedString(_msg.ErrMsgTemplate.NO_SSH_AGENT_FOUND)
        )
    except NotImplementedError:
        error_callback(_msg.TranslatedString(_msg.ErrMsgTemplate.NO_AF_UNIX))
    except OSError as exc:
        error_callback(
            _msg.TranslatedString(
                _msg.ErrMsgTemplate.CANNOT_CONNECT_TO_AGENT,
                error=exc.strerror,
                filename=exc.filename,
            ).maybe_without_filename()
        )
    except RuntimeError as exc:
        error_callback(
            _msg.TranslatedString(_msg.ErrMsgTemplate.CANNOT_UNDERSTAND_AGENT),
            exc_info=exc,
        )


def _print_config_as_sh_script(
    config: _types.VaultConfig,
    /,
    *,
    outfile: TextIO,
    prog_name_list: Sequence[str],
) -> None:
    service_keys = (
        'length',
        'repeat',
        'lower',
        'upper',
        'number',
        'space',
        'dash',
        'symbol',
    )
    print('#!/bin/sh -e', file=outfile)
    print(file=outfile)
    print(shlex.join([*prog_name_list, '--clear']), file=outfile)
    sv_obj_pairs: list[
        tuple[
            str | None,
            _types.VaultConfigGlobalSettings
            | _types.VaultConfigServicesSettings,
        ],
    ] = list(config['services'].items())
    if config.get('global', {}):
        sv_obj_pairs.insert(0, (None, config['global']))
    for sv, sv_obj in sv_obj_pairs:
        this_service_keys = tuple(k for k in service_keys if k in sv_obj)
        this_other_keys = tuple(k for k in sv_obj if k not in service_keys)
        if this_other_keys:
            other_sv_obj = {k: sv_obj[k] for k in this_other_keys}  # type: ignore[literal-required]
            dumped_config = json.dumps(
                (
                    {'services': {sv: other_sv_obj}}
                    if sv is not None
                    else {'global': other_sv_obj, 'services': {}}
                ),
                ensure_ascii=False,
                indent=None,
            )
            print(
                shlex.join([*prog_name_list, '--import', '-']) + " <<'HERE'",
                dumped_config,
                'HERE',
                sep='\n',
                file=outfile,
            )
        if not this_service_keys and not this_other_keys and sv:
            dumped_config = json.dumps(
                {'services': {sv: {}}},
                ensure_ascii=False,
                indent=None,
            )
            print(
                shlex.join([*prog_name_list, '--import', '-']) + " <<'HERE'",
                dumped_config,
                'HERE',
                sep='\n',
                file=outfile,
            )
        elif this_service_keys:
            tokens = [*prog_name_list, '--config']
            for key in this_service_keys:
                tokens.extend([f'--{key}', str(sv_obj[key])])  # type: ignore[literal-required]
            if sv is not None:
                tokens.extend(['--', sv])
            print(shlex.join(tokens), file=outfile)


# Concrete option groups used by this command-line interface.
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
        except ValueError as exc:
            raise click.BadParameter(_NOT_AN_INTEGER) from exc
    if int_value < 0:
        raise click.BadParameter(_NOT_A_NONNEGATIVE_INTEGER)
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
        except ValueError as exc:
            raise click.BadParameter(_NOT_AN_INTEGER) from exc
    if int_value < 1:
        raise click.BadParameter(_NOT_A_POSITIVE_INTEGER)
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
    help=(
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_VAULT_01),
        _msg.TranslatedString(
            _msg.Label.DERIVEPASSPHRASE_VAULT_02,
            service_metavar=_msg.TranslatedString(
                _msg.Label.VAULT_METAVAR_SERVICE
            ),
        ),
    ),
    epilog=(
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_VAULT_EPILOG_01),
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_VAULT_EPILOG_02),
    ),
)
@click.option(
    '-p',
    '--phrase',
    'use_phrase',
    is_flag=True,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_PHRASE_HELP_TEXT
    ),
    cls=PassphraseGenerationOption,
)
@click.option(
    '-k',
    '--key',
    'use_key',
    is_flag=True,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_KEY_HELP_TEXT
    ),
    cls=PassphraseGenerationOption,
)
@click.option(
    '-l',
    '--length',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=_validate_length,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_LENGTH_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=PassphraseGenerationOption,
)
@click.option(
    '-r',
    '--repeat',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=_validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_REPEAT_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=PassphraseGenerationOption,
)
@click.option(
    '--lower',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=_validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_LOWER_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=PassphraseGenerationOption,
)
@click.option(
    '--upper',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=_validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_UPPER_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=PassphraseGenerationOption,
)
@click.option(
    '--number',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=_validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_NUMBER_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=PassphraseGenerationOption,
)
@click.option(
    '--space',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=_validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_SPACE_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=PassphraseGenerationOption,
)
@click.option(
    '--dash',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=_validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_DASH_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=PassphraseGenerationOption,
)
@click.option(
    '--symbol',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=_validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_SYMBOL_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=PassphraseGenerationOption,
)
@click.option(
    '-n',
    '--notes',
    'edit_notes',
    is_flag=True,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_NOTES_HELP_TEXT,
        service_metavar=_msg.TranslatedString(
            _msg.Label.VAULT_METAVAR_SERVICE
        ),
    ),
    cls=ConfigurationOption,
)
@click.option(
    '-c',
    '--config',
    'store_config_only',
    is_flag=True,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_CONFIG_HELP_TEXT,
        service_metavar=_msg.TranslatedString(
            _msg.Label.VAULT_METAVAR_SERVICE
        ),
    ),
    cls=ConfigurationOption,
)
@click.option(
    '-x',
    '--delete',
    'delete_service_settings',
    is_flag=True,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_DELETE_HELP_TEXT,
        service_metavar=_msg.TranslatedString(
            _msg.Label.VAULT_METAVAR_SERVICE
        ),
    ),
    cls=ConfigurationOption,
)
@click.option(
    '--delete-globals',
    is_flag=True,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_DELETE_GLOBALS_HELP_TEXT,
    ),
    cls=ConfigurationOption,
)
@click.option(
    '-X',
    '--clear',
    'clear_all_settings',
    is_flag=True,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_DELETE_ALL_HELP_TEXT,
    ),
    cls=ConfigurationOption,
)
@click.option(
    '-e',
    '--export',
    'export_settings',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_EXPORT_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=StorageManagementOption,
    shell_complete=_shell_complete_path,
)
@click.option(
    '-i',
    '--import',
    'import_settings',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_IMPORT_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=StorageManagementOption,
    shell_complete=_shell_complete_path,
)
@click.option(
    '--overwrite-existing/--merge-existing',
    'overwrite_config',
    default=False,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_OVERWRITE_HELP_TEXT
    ),
    cls=CompatibilityOption,
)
@click.option(
    '--unset',
    'unset_settings',
    multiple=True,
    type=click.Choice([
        'phrase',
        'key',
        'length',
        'repeat',
        'lower',
        'upper',
        'number',
        'space',
        'dash',
        'symbol',
    ]),
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_UNSET_HELP_TEXT
    ),
    cls=CompatibilityOption,
)
@click.option(
    '--export-as',
    type=click.Choice(['json', 'sh']),
    default='json',
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_EXPORT_AS_HELP_TEXT
    ),
    cls=CompatibilityOption,
)
@version_option
@color_forcing_pseudo_option
@standard_logging_options
@click.argument(
    'service',
    metavar=_msg.TranslatedString(_msg.Label.VAULT_METAVAR_SERVICE),
    required=False,
    default=None,
    shell_complete=_shell_complete_service,
)
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
    unset_settings: Sequence[str] = (),
    export_as: Literal['json', 'sh'] = 'json',
) -> None:
    """Derive a passphrase using the vault(1) derivation scheme.

    This is a [`click`][CLICK]-powered command-line interface function,
    and not intended for programmatic use.  See the
    derivepassphrase-vault(1) manpage for full documentation of the
    interface.  (See also [`click.testing.CliRunner`][] for controlled,
    programmatic invocation.)

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
        unset_settings:
            Command-line argument `--unset`.  If given together with
            `--config`, unsets the specified settings (in addition to
            any other changes requested).
        export_as:
            Command-line argument `--export-as`.  If given together with
            `--export`, selects the format to export the current
            configuration as: JSON ("json", default) or POSIX sh ("sh").

    """  # noqa: DOC501
    logger = logging.getLogger(PROG_NAME)
    deprecation = logging.getLogger(PROG_NAME + '.deprecation')
    service_metavar = _msg.TranslatedString(_msg.Label.VAULT_METAVAR_SERVICE)
    options_in_group: dict[type[click.Option], list[click.Option]] = {}
    params_by_str: dict[str, click.Parameter] = {}
    for param in ctx.command.params:
        if isinstance(param, click.Option):
            group: type[click.Option]
            # Use match/case here once Python 3.9 becomes unsupported.
            if isinstance(param, PassphraseGenerationOption):
                group = PassphraseGenerationOption
            elif isinstance(param, ConfigurationOption):
                group = ConfigurationOption
            elif isinstance(param, StorageManagementOption):
                group = StorageManagementOption
            elif isinstance(param, LoggingOption):
                group = LoggingOption
            elif isinstance(param, CompatibilityOption):
                group = CompatibilityOption
            elif isinstance(param, StandardOption):
                group = StandardOption
            elif isinstance(param, OptionGroupOption):  # pragma: no cover
                raise AssertionError(  # noqa: TRY003,TRY004
                    f'Unknown option group for {param!r}'  # noqa: EM102
                )
            else:
                group = click.Option
            options_in_group.setdefault(group, []).append(param)
        params_by_str[param.human_readable_name] = param
        for name in param.opts + param.secondary_opts:
            params_by_str[name] = param

    @functools.cache
    def is_param_set(param: click.Parameter) -> bool:
        return bool(ctx.params.get(param.human_readable_name))

    def option_name(param: click.Parameter | str) -> str:
        # Annoyingly, `param.human_readable_name` contains the *function*
        # parameter name, not the list of option names.  *Those* are
        # stashed in the `.opts` and `.secondary_opts` attributes, which
        # are visible in the `.to_info_dict()` output, but not otherwise
        # documented.
        param = params_by_str[param] if isinstance(param, str) else param
        names = [param.human_readable_name, *param.opts, *param.secondary_opts]
        option_names = [n for n in names if n.startswith('--')]
        return min(option_names, key=len)

    def check_incompatible_options(
        param1: click.Parameter | str,
        param2: click.Parameter | str,
    ) -> None:
        param1 = params_by_str[param1] if isinstance(param1, str) else param1
        param2 = params_by_str[param2] if isinstance(param2, str) else param2
        if param1 == param2:
            return
        if not is_param_set(param1):
            return
        if is_param_set(param2):
            param1_str = option_name(param1)
            param2_str = option_name(param2)
            raise click.BadOptionUsage(
                param1_str,
                str(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.PARAMS_MUTUALLY_EXCLUSIVE,
                        param1=param1_str,
                        param2=param2_str,
                    )
                ),
                ctx=ctx,
            )
        return

    def err(msg: Any, /, **kwargs: Any) -> NoReturn:  # noqa: ANN401
        stacklevel = kwargs.pop('stacklevel', 1)
        stacklevel += 1
        extra = kwargs.pop('extra', {})
        extra.setdefault('color', ctx.color)
        logger.error(msg, stacklevel=stacklevel, extra=extra, **kwargs)
        ctx.exit(1)

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
                _msg.TranslatedString(
                    _msg.WarnMsgTemplate.V01_STYLE_CONFIG,
                    old=old_name,
                    new=new_name,
                ),
                extra={'color': ctx.color},
            )
            if isinstance(exc, OSError):
                logger.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.FAILED_TO_MIGRATE_CONFIG,
                        path=new_name,
                        error=exc.strerror,
                        filename=exc.filename,
                    ).maybe_without_filename(),
                    extra={'color': ctx.color},
                )
            else:
                deprecation.info(
                    _msg.TranslatedString(
                        _msg.InfoMsgTemplate.SUCCESSFULLY_MIGRATED,
                        path=new_name,
                    ),
                    extra={'color': ctx.color},
                )
            return backup_config
        except OSError as exc:
            err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_LOAD_VAULT_SETTINGS,
                    error=exc.strerror,
                    filename=exc.filename,
                ).maybe_without_filename(),
            )
        except Exception as exc:  # noqa: BLE001
            err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_LOAD_VAULT_SETTINGS,
                    error=str(exc),
                    filename=None,
                ).maybe_without_filename(),
                exc_info=exc,
            )

    def put_config(config: _types.VaultConfig, /) -> None:
        try:
            _save_config(config)
        except OSError as exc:
            err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_STORE_VAULT_SETTINGS,
                    error=exc.strerror,
                    filename=exc.filename,
                ).maybe_without_filename(),
            )
        except Exception as exc:  # noqa: BLE001
            err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_STORE_VAULT_SETTINGS,
                    error=str(exc),
                    filename=None,
                ).maybe_without_filename(),
                exc_info=exc,
            )

    def get_user_config() -> dict[str, Any]:
        try:
            return _load_user_config()
        except FileNotFoundError:
            return {}
        except OSError as exc:
            err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_LOAD_USER_CONFIG,
                    error=exc.strerror,
                    filename=exc.filename,
                ).maybe_without_filename(),
            )
        except Exception as exc:  # noqa: BLE001
            err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_LOAD_USER_CONFIG,
                    error=str(exc),
                    filename=None,
                ).maybe_without_filename(),
                exc_info=exc,
            )

    configuration: _types.VaultConfig

    check_incompatible_options('--phrase', '--key')
    for group in (ConfigurationOption, StorageManagementOption):
        for opt in options_in_group[group]:
            if opt != params_by_str['--config']:
                for other_opt in options_in_group[PassphraseGenerationOption]:
                    check_incompatible_options(opt, other_opt)

    for group in (ConfigurationOption, StorageManagementOption):
        for opt in options_in_group[group]:
            for other_opt in options_in_group[ConfigurationOption]:
                check_incompatible_options(opt, other_opt)
            for other_opt in options_in_group[StorageManagementOption]:
                check_incompatible_options(opt, other_opt)
    sv_or_global_options = options_in_group[PassphraseGenerationOption]
    for param in sv_or_global_options:
        if is_param_set(param) and not (
            service is not None or is_param_set(params_by_str['--config'])
        ):
            err_msg = _msg.TranslatedString(
                _msg.ErrMsgTemplate.PARAMS_NEEDS_SERVICE_OR_CONFIG,
                param=param.opts[0],
                service_metavar=service_metavar,
            )
            raise click.UsageError(str(err_msg))
    sv_options = [params_by_str['--notes'], params_by_str['--delete']]
    for param in sv_options:
        if is_param_set(param) and not service is not None:
            err_msg = _msg.TranslatedString(
                _msg.ErrMsgTemplate.PARAMS_NEEDS_SERVICE,
                param=param.opts[0],
                service_metavar=service_metavar,
            )
            raise click.UsageError(str(err_msg))
    no_sv_options = [
        params_by_str['--delete-globals'],
        params_by_str['--clear'],
        *options_in_group[StorageManagementOption],
    ]
    for param in no_sv_options:
        if is_param_set(param) and service is not None:
            err_msg = _msg.TranslatedString(
                _msg.ErrMsgTemplate.PARAMS_NO_SERVICE,
                param=param.opts[0],
                service_metavar=service_metavar,
            )
            raise click.UsageError(str(err_msg))

    user_config = get_user_config()

    if service == '':  # noqa: PLC1901
        logger.warning(
            _msg.TranslatedString(
                _msg.WarnMsgTemplate.EMPTY_SERVICE_NOT_SUPPORTED,
                service_metavar=service_metavar,
            ),
            extra={'color': ctx.color},
        )

    if edit_notes:
        assert service is not None
        configuration = get_config()
        text = DEFAULT_NOTES_TEMPLATE + configuration['services'].get(
            service, cast('_types.VaultConfigServicesSettings', {})
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
                    err(
                        _msg.TranslatedString(
                            _msg.ErrMsgTemplate.USER_ABORTED_EDIT
                        )
                    )
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
            infile = cast(
                'TextIO',
                (
                    import_settings
                    if hasattr(import_settings, 'close')
                    else click.open_file(os.fspath(import_settings), 'rt')
                ),
            )
            # Don't specifically catch TypeError or ValueError here if
            # the passed-in fileobj is not a readable text stream.  This
            # will never happen on the command-line (thanks to `click`),
            # and for programmatic use, our caller may want accurate
            # error information.
            with infile:
                maybe_config = json.load(infile)
        except json.JSONDecodeError as exc:
            err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_DECODEIMPORT_VAULT_SETTINGS,
                    error=exc,
                )
            )
        except OSError as exc:
            err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_IMPORT_VAULT_SETTINGS,
                    error=exc.strerror,
                    filename=exc.filename,
                ).maybe_without_filename()
            )
        cleaned = _types.clean_up_falsy_vault_config_values(maybe_config)
        if not _types.is_vault_config(maybe_config):
            err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_IMPORT_VAULT_SETTINGS,
                    error=_msg.TranslatedString(
                        _msg.ErrMsgTemplate.INVALID_VAULT_CONFIG,
                        config=maybe_config,
                    ),
                    filename=None,
                ).maybe_without_filename()
            )
        assert cleaned is not None
        for step in cleaned:
            # These are never fatal errors, because the semantics of
            # vault upon encountering these settings are ill-specified,
            # but not ill-defined.
            if step.action == 'replace':
                logger.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.STEP_REPLACE_INVALID_VALUE,
                        old=json.dumps(step.old_value),
                        path=_types.json_path(step.path),
                        new=json.dumps(step.new_value),
                    ),
                    extra={'color': ctx.color},
                )
            else:
                logger.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.STEP_REMOVE_INEFFECTIVE_VALUE,
                        path=_types.json_path(step.path),
                        old=json.dumps(step.old_value),
                    ),
                    extra={'color': ctx.color},
                )
        if '' in maybe_config['services']:
            logger.warning(
                _msg.TranslatedString(
                    _msg.WarnMsgTemplate.EMPTY_SERVICE_SETTINGS_INACCESSIBLE,
                    service_metavar=service_metavar,
                    PROG_NAME=PROG_NAME,
                ),
                extra={'color': ctx.color},
            )
        for service_name in sorted(maybe_config['services'].keys()):
            if not _is_completable_item(service_name):
                logger.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.SERVICE_NAME_INCOMPLETABLE,
                        service=service_name,
                    ),
                    extra={'color': ctx.color},
                )
        try:
            _check_for_misleading_passphrase(
                ('global',),
                cast('dict[str, Any]', maybe_config.get('global', {})),
                main_config=user_config,
                ctx=ctx,
            )
            for key, value in maybe_config['services'].items():
                _check_for_misleading_passphrase(
                    ('services', key),
                    cast('dict[str, Any]', value),
                    main_config=user_config,
                    ctx=ctx,
                )
        except AssertionError as exc:
            err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.INVALID_USER_CONFIG,
                    error=exc,
                    filename=None,
                ).maybe_without_filename(),
            )
        global_obj = maybe_config.get('global', {})
        has_key = _types.js_truthiness(global_obj.get('key'))
        has_phrase = _types.js_truthiness(global_obj.get('phrase'))
        if has_key and has_phrase:
            logger.warning(
                _msg.TranslatedString(
                    _msg.WarnMsgTemplate.GLOBAL_PASSPHRASE_INEFFECTIVE,
                ),
                extra={'color': ctx.color},
            )
        for service_name, service_obj in maybe_config['services'].items():
            has_key = _types.js_truthiness(
                service_obj.get('key')
            ) or _types.js_truthiness(global_obj.get('key'))
            has_phrase = _types.js_truthiness(
                service_obj.get('phrase')
            ) or _types.js_truthiness(global_obj.get('phrase'))
            if has_key and has_phrase:
                logger.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.SERVICE_PASSPHRASE_INEFFECTIVE,
                        service=json.dumps(service_name),
                    ),
                    extra={'color': ctx.color},
                )
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
            outfile = cast(
                'TextIO',
                (
                    export_settings
                    if hasattr(export_settings, 'close')
                    else click.open_file(os.fspath(export_settings), 'wt')
                ),
            )
            # Don't specifically catch TypeError or ValueError here if
            # the passed-in fileobj is not a writable text stream.  This
            # will never happen on the command-line (thanks to `click`),
            # and for programmatic use, our caller may want accurate
            # error information.
            with outfile:
                if export_as == 'sh':
                    this_ctx = ctx
                    prog_name_pieces = collections.deque([
                        this_ctx.info_name or 'vault',
                    ])
                    while (
                        this_ctx.parent is not None
                        and this_ctx.parent.info_name is not None
                    ):
                        prog_name_pieces.appendleft(this_ctx.parent.info_name)
                        this_ctx = this_ctx.parent
                    _print_config_as_sh_script(
                        configuration,
                        outfile=outfile,
                        prog_name_list=prog_name_pieces,
                    )
                else:
                    json.dump(configuration, outfile)
        except OSError as exc:
            err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_EXPORT_VAULT_SETTINGS,
                    error=exc.strerror,
                    filename=exc.filename,
                ).maybe_without_filename(),
            )
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
                'dict[str, Any]',
                configuration['services'].get(service, {}) if service else {},
            ),
            cast('dict[str, Any]', configuration.get('global', {})),
        )
        if not store_config_only and not service:
            err_msg = _msg.TranslatedString(
                _msg.ErrMsgTemplate.SERVICE_REQUIRED,
                service_metavar=_msg.TranslatedString(
                    _msg.Label.VAULT_METAVAR_SERVICE
                ),
            )
            raise click.UsageError(str(err_msg))
        if use_key:
            try:
                key = base64.standard_b64encode(
                    _select_ssh_key(ctx=ctx)
                ).decode('ASCII')
            except IndexError:
                err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.USER_ABORTED_SSH_KEY_SELECTION
                    ),
                )
            except KeyError:
                err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.NO_SSH_AGENT_FOUND
                    ),
                )
            except LookupError:
                err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.NO_SUITABLE_SSH_KEYS,
                        PROG_NAME=PROG_NAME,
                    )
                )
            except NotImplementedError:
                err(_msg.TranslatedString(_msg.ErrMsgTemplate.NO_AF_UNIX))
            except OSError as exc:
                err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.CANNOT_CONNECT_TO_AGENT,
                        error=exc.strerror,
                        filename=exc.filename,
                    ).maybe_without_filename(),
                )
            except ssh_agent.SSHAgentFailedError as exc:
                err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.AGENT_REFUSED_LIST_KEYS
                    ),
                    exc_info=exc,
                )
            except RuntimeError as exc:
                err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.CANNOT_UNDERSTAND_AGENT
                    ),
                    exc_info=exc,
                )
        elif use_phrase:
            maybe_phrase = _prompt_for_passphrase()
            if not maybe_phrase:
                err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.USER_ABORTED_PASSPHRASE
                    )
                )
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
                try:
                    _check_for_misleading_passphrase(
                        ('services', service) if service else ('global',),
                        {'phrase': phrase},
                        main_config=user_config,
                        ctx=ctx,
                    )
                except AssertionError as exc:
                    err(
                        _msg.TranslatedString(
                            _msg.ErrMsgTemplate.INVALID_USER_CONFIG,
                            error=exc,
                            filename=None,
                        ).maybe_without_filename(),
                    )
                if 'key' in settings:
                    if service:
                        w_msg = _msg.TranslatedString(
                            _msg.WarnMsgTemplate.SERVICE_PASSPHRASE_INEFFECTIVE,
                            service=json.dumps(service),
                        )
                    else:
                        w_msg = _msg.TranslatedString(
                            _msg.WarnMsgTemplate.GLOBAL_PASSPHRASE_INEFFECTIVE
                        )
                    logger.warning(w_msg, extra={'color': ctx.color})
            if not view.maps[0] and not unset_settings:
                err_msg = _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_UPDATE_SETTINGS_NO_SETTINGS,
                    settings_type=_msg.TranslatedString(
                        _msg.Label.CANNOT_UPDATE_SETTINGS_METAVAR_SETTINGS_TYPE_SERVICE
                        if service
                        else _msg.Label.CANNOT_UPDATE_SETTINGS_METAVAR_SETTINGS_TYPE_GLOBAL  # noqa: E501
                    ),
                )
                raise click.UsageError(str(err_msg))
            for setting in unset_settings:
                if setting in view.maps[0]:
                    err_msg = _msg.TranslatedString(
                        _msg.ErrMsgTemplate.SET_AND_UNSET_SAME_SETTING,
                        setting=setting,
                    )
                    raise click.UsageError(str(err_msg))
            if not _is_completable_item(service):
                logger.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.SERVICE_NAME_INCOMPLETABLE,
                        service=service,
                    ),
                    extra={'color': ctx.color},
                )
            subtree: dict[str, Any] = (
                configuration['services'].setdefault(service, {})  # type: ignore[assignment]
                if service
                else configuration.setdefault('global', {})
            )
            if overwrite_config:
                subtree.clear()
            else:
                for setting in unset_settings:
                    subtree.pop(setting, None)
            subtree.update(view)
            assert _types.is_vault_config(configuration), (
                f'Invalid vault configuration: {configuration!r}'
            )
            put_config(configuration)
        else:
            assert service is not None
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
                        ctx=ctx,
                    )
                except AssertionError as exc:
                    err(
                        _msg.TranslatedString(
                            _msg.ErrMsgTemplate.INVALID_USER_CONFIG,
                            error=exc,
                            filename=None,
                        ).maybe_without_filename(),
                    )

            # If either --key or --phrase are given, use that setting.
            # Otherwise, if both key and phrase are set in the config,
            # use the key.  Otherwise, if only one of key and phrase is
            # set in the config, use that one.  In all these above
            # cases, set the phrase via vault.Vault.phrase_from_key if
            # a key is given.  Finally, if nothing is set, error out.
            if use_key or use_phrase:
                kwargs['phrase'] = (
                    _key_to_phrase(key, error_callback=err)
                    if use_key
                    else phrase
                )
            elif kwargs.get('key'):
                kwargs['phrase'] = _key_to_phrase(
                    kwargs['key'], error_callback=err
                )
            elif kwargs.get('phrase'):
                pass
            else:
                err_msg = _msg.TranslatedString(
                    _msg.ErrMsgTemplate.NO_KEY_OR_PHRASE
                )
                raise click.UsageError(str(err_msg))
            kwargs.pop('key', '')
            result = vault.Vault(**kwargs).generate(service)
            click.echo(result.decode('ASCII'), color=ctx.color)


if __name__ == '__main__':
    derivepassphrase()
