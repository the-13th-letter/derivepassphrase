# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

# ruff: noqa: TRY400

"""Command-line interface for derivepassphrase."""

from __future__ import annotations

import base64
import collections
import contextlib
import json
import logging
import os
from typing import (
    TYPE_CHECKING,
    Final,
    Literal,
    NoReturn,
    TextIO,
    cast,
)

import click
import click.shell_completion
from typing_extensions import (
    Any,
)

from derivepassphrase import _internals, _types, exporter, ssh_agent, vault
from derivepassphrase._internals import cli_helpers, cli_machinery
from derivepassphrase._internals import cli_messages as _msg

if TYPE_CHECKING:
    from collections.abc import Sequence
    from collections.abc import Set as AbstractSet
    from contextlib import AbstractContextManager

__all__ = ('derivepassphrase',)

PROG_NAME = _internals.PROG_NAME
VERSION = _internals.VERSION


@click.group(
    context_settings={
        'help_option_names': ['-h', '--help'],
        'ignore_unknown_options': True,
        'allow_interspersed_args': False,
    },
    epilog=_msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_EPILOG_01),
    invoke_without_command=True,
    cls=cli_machinery.TopLevelCLIEntryPoint,
    help=(
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_01),
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_02),
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_03),
    ),
)
@cli_machinery.version_option(
    cli_machinery.derivepassphrase_version_option_callback
)
@cli_machinery.color_forcing_pseudo_option
@cli_machinery.standard_logging_options
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
    # TODO(the-13th-letter): Turn this callback into a no-op in v1.0.
    # https://the13thletter.info/derivepassphrase/latest/upgrade-notes/#v1.0-implied-subcommands
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
    cls=cli_machinery.DefaultToVaultGroup,
    help=(
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_EXPORT_01),
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_EXPORT_02),
        _msg.TranslatedString(_msg.Label.DERIVEPASSPHRASE_EXPORT_03),
    ),
)
@cli_machinery.version_option(cli_machinery.export_version_option_callback)
@cli_machinery.color_forcing_pseudo_option
@cli_machinery.standard_logging_options
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
    # TODO(the-13th-letter): Turn this callback into a no-op in v1.0.
    # https://the13thletter.info/derivepassphrase/latest/upgrade-notes/#v1.0-implied-subcommands
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


@derivepassphrase_export.command(
    'vault',
    context_settings={'help_option_names': ['-h', '--help']},
    cls=cli_machinery.CommandWithHelpGroups,
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
    cls=cli_machinery.StandardOption,
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
    cls=cli_machinery.StandardOption,
)
@cli_machinery.version_option(
    cli_machinery.export_vault_version_option_callback
)
@cli_machinery.color_forcing_pseudo_option
@cli_machinery.standard_logging_options
@click.argument(
    'path',
    metavar=_msg.TranslatedString(_msg.Label.EXPORT_VAULT_METAVAR_PATH),
    required=True,
    shell_complete=cli_helpers.shell_complete_path,
)
@click.pass_context
def derivepassphrase_export_vault(
    ctx: click.Context,
    /,
    *,
    path: str | bytes | os.PathLike[str] | None,
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
        path = None
    if isinstance(key, str):  # pragma: no branch
        key = key.encode('utf-8')
    for fmt in formats:
        try:
            config = exporter.export_vault_config_data(path, key, format=fmt)
        except (
            IsADirectoryError,
            NotADirectoryError,
            exporter.NotAVaultConfigError,
            RuntimeError,
        ):
            logger.info(
                _msg.TranslatedString(
                    _msg.InfoMsgTemplate.CANNOT_LOAD_AS_VAULT_CONFIG,
                    path=path or exporter.get_vault_path(),
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
                json.dumps(
                    config, ensure_ascii=False, indent=2, sort_keys=True
                ),
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


class _VaultContext:  # noqa: PLR0904
    """The context for the "vault" command-line interface.

    This context object -- wrapping a [`click.Context`][] object --
    encapsulates a single call to the `derivepassphrase vault`
    command-line.  Although fully documented, this class is an
    implementation detail of the `derivepassphrase vault` command-line
    and should not be instantiated directly by users or API clients.

    Attributes:
        logger:
            The logger used for warnings and error messages.
        deprecation:
            The logger used for deprecation warnings.
        ctx:
            The underlying [`click.Context`][] from which the
            command-line settings and parameter values are queried.
        all_ops:
            A list of operations supported by the CLI, in the
            order that they are queried in the `click` context.  The
            final entry is the default operation, and does not
            correspond to a `click` parameter; all others are `click`
            parameter names.
        readwrite_ops:
            A set of operations which modify the `derivepassphrase`
            state.  All other operations are read-only.
        options_in_group:
            A mapping of option group names to lists of known options
            from this group.  Used during the validation of the command
            line.
        params_by_str:
            A mapping of option names (long names, short names, etc.) to
            option objects.  Used during the validation of the command
            line.

    """

    logger: Final = logging.getLogger(PROG_NAME)
    """"""
    deprecation: Final = logging.getLogger(PROG_NAME + '.deprecation')
    """"""
    ctx: Final[click.Context]
    """"""
    all_ops: tuple[str, ...] = (
        'delete_service_settings',
        'delete_globals',
        'clear_all_settings',
        'import_settings',
        'export_settings',
        'store_config_only',
        # The default op "derive_passphrase" must be last!
        'derive_passphrase',
    )
    readwrite_ops: AbstractSet[str] = frozenset({
        'delete_service_settings',
        'delete_globals',
        'clear_all_settings',
        'import_settings',
        'store_config_only',
    })
    options_in_group: dict[type[click.Option], list[click.Option]]
    params_by_str: dict[str, click.Parameter]

    def __init__(self, ctx: click.Context, /) -> None:
        """Initialize the vault context.

        Args:
            ctx:
                The underlying [`click.Context`][] from which the
                command-line settings and parameter values are queried.

        """
        self.ctx = ctx
        self.params_by_str = {}
        self.options_in_group = {}
        for param in ctx.command.params:
            if isinstance(param, click.Option):
                group: type[click.Option]
                known_option_groups = [
                    cli_machinery.PassphraseGenerationOption,
                    cli_machinery.ConfigurationOption,
                    cli_machinery.StorageManagementOption,
                    cli_machinery.LoggingOption,
                    cli_machinery.CompatibilityOption,
                    cli_machinery.StandardOption,
                ]
                if isinstance(param, cli_machinery.OptionGroupOption):
                    for class_ in known_option_groups:
                        if isinstance(param, class_):
                            group = class_
                            break
                    else:  # pragma: no cover
                        assert False, f'Unknown option group for {param!r}'  # noqa: B011,PT015
                else:
                    group = click.Option
                self.options_in_group.setdefault(group, []).append(param)
            self.params_by_str[param.human_readable_name] = param
            for name in param.opts + param.secondary_opts:
                self.params_by_str[name] = param

    def is_param_set(self, param: click.Parameter, /) -> bool:
        """Return true if the parameter is set."""
        return bool(self.ctx.params.get(param.human_readable_name))

    def option_name(self, param: click.Parameter | str, /) -> str:
        """Return the option name of a parameter.

        Annoyingly, `param.human_readable_name` contains the *function*
        parameter name, not the list of option names.  *Those* are
        stashed in the `.opts` and `.secondary_opts` attributes, which
        are visible in the `.to_info_dict()` output, but not otherwise
        documented.  We return the shortest one among the long-form
        option names.

        Args:
            param: The parameter whose option name is requested.

        Raises:
            ValueError: The parameter has no long-form option names.

        """
        param = self.params_by_str[param] if isinstance(param, str) else param
        names = [param.human_readable_name, *param.opts, *param.secondary_opts]
        option_names = [n for n in names if n.startswith('--')]
        return min(option_names, key=len)

    def check_incompatible_options(
        self,
        param1: click.Parameter | str,
        param2: click.Parameter | str,
    ) -> None:
        """Raise an error if the two options are incompatible.

        Raises:
            click.BadOptionUsage: The given options are incompatible.

        """
        param1 = (
            self.params_by_str[param1] if isinstance(param1, str) else param1
        )
        param2 = (
            self.params_by_str[param2] if isinstance(param2, str) else param2
        )
        if param1 == param2:
            return
        if not self.is_param_set(param1):
            return
        if self.is_param_set(param2):
            param1_str = self.option_name(param1)
            param2_str = self.option_name(param2)
            raise click.BadOptionUsage(
                param1_str,
                str(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.PARAMS_MUTUALLY_EXCLUSIVE,
                        param1=param1_str,
                        param2=param2_str,
                    )
                ),
                ctx=self.ctx,
            )
        return

    def err(self, msg: Any, /, **kwargs: Any) -> NoReturn:  # noqa: ANN401
        """Log an error, then abort the function call.

        We ensure that color handling is done properly before the error
        is logged.

        """
        stacklevel = kwargs.pop('stacklevel', 1)
        stacklevel += 1
        extra = kwargs.pop('extra', {})
        extra.setdefault('color', self.ctx.color)
        self.logger.error(msg, stacklevel=stacklevel, extra=extra, **kwargs)
        self.ctx.exit(1)

    def warning(self, msg: Any, /, **kwargs: Any) -> None:  # noqa: ANN401
        """Log a warning.

        We ensure that color handling is done properly before the
        warning is logged.

        """
        stacklevel = kwargs.pop('stacklevel', 1)
        stacklevel += 1
        extra = kwargs.pop('extra', {})
        extra.setdefault('color', self.ctx.color)
        self.logger.warning(msg, stacklevel=stacklevel, extra=extra, **kwargs)

    def deprecation_warning(self, msg: Any, /, **kwargs: Any) -> None:  # noqa: ANN401
        """Log a deprecation warning.

        We ensure that color handling is done properly before the
        warning is logged.

        """
        stacklevel = kwargs.pop('stacklevel', 1)
        stacklevel += 1
        extra = kwargs.pop('extra', {})
        extra.setdefault('color', self.ctx.color)
        self.deprecation.warning(
            msg, stacklevel=stacklevel, extra=extra, **kwargs
        )

    def deprecation_info(self, msg: Any, /, **kwargs: Any) -> None:  # noqa: ANN401
        """Log a deprecation info message.

        We ensure that color handling is done properly before the
        warning is logged.

        """
        stacklevel = kwargs.pop('stacklevel', 1)
        stacklevel += 1
        extra = kwargs.pop('extra', {})
        extra.setdefault('color', self.ctx.color)
        self.deprecation.info(
            msg, stacklevel=stacklevel, extra=extra, **kwargs
        )

    def get_config(self) -> _types.VaultConfig:
        """Return the vault configuration stored on disk.

        If no configuration is stored, return an empty configuration.

        If only a v0.1-style configuration is found, attempt to migrate
        it.  This will be removed in v1.0.

        """
        try:
            return cli_helpers.load_config()
        except FileNotFoundError:
            # TODO(the-13th-letter): Return the empty default
            # configuration directly.
            # https://the13thletter.info/derivepassphrase/latest/upgrade-notes.html#v1.0-old-settings-file
            try:
                backup_config, exc = cli_helpers.migrate_and_load_old_config()
            except FileNotFoundError:
                return {'services': {}}
            old_name = cli_helpers.config_filename(
                subsystem='old settings.json'
            ).name
            new_name = cli_helpers.config_filename(subsystem='vault').name
            self.deprecation_warning(
                _msg.TranslatedString(
                    _msg.WarnMsgTemplate.V01_STYLE_CONFIG,
                    old=old_name,
                    new=new_name,
                ),
            )
            if isinstance(exc, OSError):
                self.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.FAILED_TO_MIGRATE_CONFIG,
                        path=new_name,
                        error=exc.strerror,
                        filename=exc.filename,
                    ).maybe_without_filename(),
                )
            else:
                self.deprecation_info(
                    _msg.TranslatedString(
                        _msg.InfoMsgTemplate.SUCCESSFULLY_MIGRATED,
                        path=new_name,
                    ),
                )
            return backup_config
        except OSError as exc:
            self.err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_LOAD_VAULT_SETTINGS,
                    error=exc.strerror,
                    filename=exc.filename,
                ).maybe_without_filename(),
            )
        except Exception as exc:  # noqa: BLE001
            self.err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_LOAD_VAULT_SETTINGS,
                    error=str(exc),
                    filename=None,
                ).maybe_without_filename(),
                exc_info=exc,
            )

    def put_config(self, config: _types.VaultConfig, /) -> None:
        """Store the given vault configuration to disk."""
        try:
            cli_helpers.save_config(config)
        except OSError as exc:
            self.err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_STORE_VAULT_SETTINGS,
                    error=exc.strerror,
                    filename=exc.filename,
                ).maybe_without_filename(),
            )
        except Exception as exc:  # noqa: BLE001
            self.err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_STORE_VAULT_SETTINGS,
                    error=str(exc),
                    filename=None,
                ).maybe_without_filename(),
                exc_info=exc,
            )

    def get_user_config(self) -> dict[str, Any]:
        """Return the global user configuration stored on disk.

        If no configuration is stored, return an empty configuration.

        """
        try:
            return cli_helpers.load_user_config()
        except FileNotFoundError:
            return {}
        except OSError as exc:
            self.err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_LOAD_USER_CONFIG,
                    error=exc.strerror,
                    filename=exc.filename,
                ).maybe_without_filename(),
            )
        except Exception as exc:  # noqa: BLE001
            self.err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_LOAD_USER_CONFIG,
                    error=str(exc),
                    filename=None,
                ).maybe_without_filename(),
                exc_info=exc,
            )

    def validate_command_line(self) -> None:  # noqa: C901,PLR0912
        """Check for missing/extra arguments and conflicting options.

        Raises:
            click.UsageError:
                The command-line is invalid because of missing or extra
                arguments, or because of conflicting options.  The error
                message contains further details.

        """
        param: click.Parameter
        self.check_incompatible_options('--phrase', '--key')
        for group in (
            cli_machinery.ConfigurationOption,
            cli_machinery.StorageManagementOption,
        ):
            for opt in self.options_in_group[group]:
                if opt not in {
                    self.params_by_str['--config'],
                    self.params_by_str['--notes'],
                }:
                    for other_opt in self.options_in_group[
                        cli_machinery.PassphraseGenerationOption
                    ]:
                        self.check_incompatible_options(opt, other_opt)

        for group in (
            cli_machinery.ConfigurationOption,
            cli_machinery.StorageManagementOption,
        ):
            for opt in self.options_in_group[group]:
                for other_opt in self.options_in_group[
                    cli_machinery.ConfigurationOption
                ]:
                    if {opt, other_opt} != {
                        self.params_by_str['--config'],
                        self.params_by_str['--notes'],
                    }:
                        self.check_incompatible_options(opt, other_opt)
                for other_opt in self.options_in_group[
                    cli_machinery.StorageManagementOption
                ]:
                    self.check_incompatible_options(opt, other_opt)
        service: str | None = self.ctx.params['service']
        service_metavar = _msg.TranslatedString(
            _msg.Label.VAULT_METAVAR_SERVICE
        )
        sv_or_global_options = self.options_in_group[
            cli_machinery.PassphraseGenerationOption
        ]
        for param in sv_or_global_options:
            if self.is_param_set(param) and not (
                service is not None
                or self.is_param_set(self.params_by_str['--config'])
            ):
                err_msg = _msg.TranslatedString(
                    _msg.ErrMsgTemplate.PARAMS_NEEDS_SERVICE_OR_CONFIG,
                    param=param.opts[0],
                    service_metavar=service_metavar,
                )
                raise click.UsageError(str(err_msg))
        sv_options = [
            self.params_by_str['--notes'],
            self.params_by_str['--delete'],
        ]
        for param in sv_options:
            if self.is_param_set(param) and not service is not None:
                err_msg = _msg.TranslatedString(
                    _msg.ErrMsgTemplate.PARAMS_NEEDS_SERVICE,
                    param=param.opts[0],
                    service_metavar=service_metavar,
                )
                raise click.UsageError(str(err_msg))
        no_sv_options = [
            self.params_by_str['--delete-globals'],
            self.params_by_str['--clear'],
            *self.options_in_group[cli_machinery.StorageManagementOption],
        ]
        for param in no_sv_options:
            if self.is_param_set(param) and service is not None:
                err_msg = _msg.TranslatedString(
                    _msg.ErrMsgTemplate.PARAMS_NO_SERVICE,
                    param=param.opts[0],
                    service_metavar=service_metavar,
                )
                raise click.UsageError(str(err_msg))

    def get_mutex(
        self,
        op: str,
    ) -> AbstractContextManager[AbstractContextManager | None]:
        """Return a mutex for accessing the configuration on disk.

        The mutex is a context manager, and will lock out other threads
        and processes attempting to access the configuration in an
        incompatible manner.

        Returns:
            If the requested operation is a read-only operation, return
            a no-op mutex.  (Concurrent reads are always allowed, even
            in the presence of writers.)  Otherwise, for read-write
            operations, return an actual mutex.

        """
        return (
            cli_helpers.configuration_mutex()
            if op in self.readwrite_ops
            else contextlib.nullcontext()
        )

    def dispatch_op(self) -> None:
        """Dispatch to the handler matching the command-line call.

        Also issue any appropriate warnings about the command-line,
        e.g., incompatibilities with vault(1) or ineffective options.

        """
        service_metavar = _msg.TranslatedString(
            _msg.Label.VAULT_METAVAR_SERVICE
        )
        if self.ctx.params['service'] == '':  # noqa: PLC1901
            self.warning(
                _msg.TranslatedString(
                    _msg.WarnMsgTemplate.EMPTY_SERVICE_NOT_SUPPORTED,
                    service_metavar=service_metavar,
                ),
            )
        if self.ctx.params.get('edit_notes') and not self.ctx.params.get(
            'store_config_only'
        ):
            self.warning(
                _msg.TranslatedString(
                    _msg.WarnMsgTemplate.EDITING_NOTES_BUT_NOT_STORING_CONFIG,
                    service_metavar=service_metavar,
                ),
            )
        op: str
        for candidate_op in self.all_ops[:-1]:
            if self.ctx.params.get(candidate_op):
                op = candidate_op
                break
        else:
            op = self.all_ops[-1]
        with self.get_mutex(op):
            op_func = getattr(self, 'run_op_' + op)
            return op_func()

    def run_op_delete_service_settings(self) -> None:
        """Delete settings for a specific service."""
        service = self.ctx.params['service']
        assert service is not None
        configuration = self.get_config()
        if service in configuration['services']:
            del configuration['services'][service]
            self.put_config(configuration)

    def run_op_delete_globals(self) -> None:
        """Delete the global settings."""
        configuration = self.get_config()
        if 'global' in configuration:
            del configuration['global']
            self.put_config(configuration)

    def run_op_clear_all_settings(self) -> None:
        """Clear all settings."""
        self.put_config({'services': {}})

    def run_op_import_settings(self) -> None:  # noqa: C901,PLR0912
        """Import settings from a given file.

        Issue multiple warnings, if appropriate, e.g. for Unicode
        normalization issues with stored passphrases or conflicting
        stored passphrases and keys.  Respect the `--overwrite-config`
        and `--merge-config` options when writing the imported
        configuration to disk.

        """
        service_metavar = _msg.TranslatedString(
            _msg.Label.VAULT_METAVAR_SERVICE
        )
        user_config = self.get_user_config()
        import_settings = self.ctx.params['import_settings']
        overwrite_config = self.ctx.params['overwrite_config']
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
            self.err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_DECODEIMPORT_VAULT_SETTINGS,
                    error=exc,
                )
            )
        except OSError as exc:
            self.err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_IMPORT_VAULT_SETTINGS,
                    error=exc.strerror,
                    filename=exc.filename,
                ).maybe_without_filename()
            )
        cleaned = _types.clean_up_falsy_vault_config_values(maybe_config)
        if not _types.is_vault_config(maybe_config):
            self.err(
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
                self.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.STEP_REPLACE_INVALID_VALUE,
                        old=json.dumps(step.old_value),
                        path=_types.json_path(step.path),
                        new=json.dumps(step.new_value),
                    ),
                )
            else:
                self.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.STEP_REMOVE_INEFFECTIVE_VALUE,
                        path=_types.json_path(step.path),
                        old=json.dumps(step.old_value),
                    ),
                )
        if '' in maybe_config['services']:
            self.warning(
                _msg.TranslatedString(
                    _msg.WarnMsgTemplate.EMPTY_SERVICE_SETTINGS_INACCESSIBLE,
                    service_metavar=service_metavar,
                    PROG_NAME=PROG_NAME,
                ),
            )
        for service_name in sorted(maybe_config['services'].keys()):
            if not cli_helpers.is_completable_item(service_name):
                self.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.SERVICE_NAME_INCOMPLETABLE,
                        service=service_name,
                    ),
                )
        try:
            cli_helpers.check_for_misleading_passphrase(
                ('global',),
                cast('dict[str, Any]', maybe_config.get('global', {})),
                main_config=user_config,
                ctx=self.ctx,
            )
            for key, value in maybe_config['services'].items():
                cli_helpers.check_for_misleading_passphrase(
                    ('services', key),
                    cast('dict[str, Any]', value),
                    main_config=user_config,
                    ctx=self.ctx,
                )
        except AssertionError as exc:
            self.err(
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
            self.warning(
                _msg.TranslatedString(
                    _msg.WarnMsgTemplate.GLOBAL_PASSPHRASE_INEFFECTIVE,
                ),
            )
        for service_name, service_obj in maybe_config['services'].items():
            has_key = _types.js_truthiness(
                service_obj.get('key')
            ) or _types.js_truthiness(global_obj.get('key'))
            has_phrase = _types.js_truthiness(
                service_obj.get('phrase')
            ) or _types.js_truthiness(global_obj.get('phrase'))
            if has_key and has_phrase:
                self.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.SERVICE_PASSPHRASE_INEFFECTIVE,
                        service=json.dumps(service_name),
                    ),
                )
        if overwrite_config:
            self.put_config(maybe_config)
        else:
            configuration = self.get_config()
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
            self.put_config(new_config)

    def run_op_export_settings(self) -> None:
        """Export settings to a given file.

        Respect the `--export-as` option when writing the exported
        configuration to the file.

        """
        export_settings = self.ctx.params['export_settings']
        export_as = self.ctx.params['export_as']
        configuration = self.get_config()
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
                    this_ctx = self.ctx
                    prog_name_pieces = collections.deque([
                        this_ctx.info_name or 'vault',
                    ])
                    while (
                        this_ctx.parent is not None
                        and this_ctx.parent.info_name is not None
                    ):
                        prog_name_pieces.appendleft(this_ctx.parent.info_name)
                        this_ctx = this_ctx.parent
                    cli_helpers.print_config_as_sh_script(
                        configuration,
                        outfile=outfile,
                        prog_name_list=prog_name_pieces,
                    )
                else:
                    json.dump(
                        configuration,
                        outfile,
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
        except OSError as exc:
            self.err(
                _msg.TranslatedString(
                    _msg.ErrMsgTemplate.CANNOT_EXPORT_VAULT_SETTINGS,
                    error=exc.strerror,
                    filename=exc.filename,
                ).maybe_without_filename(),
            )

    def run_subop_query_phrase_or_key_change(  # noqa: C901,PLR0912
        self,
        *,
        empty_service_permitted: bool,
        configuration: _types.VaultConfig | None = None,
    ) -> collections.ChainMap[str, Any]:
        """Query the master passphrase or master SSH key, if changed.

        If the user indicates they want to change the master passphrase
        or master SSH key for this call, or if they want to configure
        a stored global or service-specific master passphrase or master
        SSH key, then query the user.

        This is not a complete command-line call operation in and of
        itself.

        Args:
            empty_service_permitted:
                True if an empty service name is permitted, False otherwise.
            configuration:
                The vault configuration, parsed from disk.  If not
                given, we read the configuration from disk ourselves.

                The returned effective configuration already contains
                a relevant slice of the vault configuration. However,
                some callers need access to the full configuration *and*
                need the slice within the effective configuration to
                refer to the same object.

        Returns:
            The effective configuration for the (possibly empty) given
            service, as a [chained map][collections.ChainMap].  Any
            master passphrase or master SSH key overrides that may be in
            effect are stored in the first map.

        Raises:
            click.UsageError:
                The service name was empty, and an empty service name
                was not permitted as per the method parameters.

        Warning:
            It is the caller's responsibility to vet any interactively
            entered master passphrase for Unicode normalization issues.

        """
        service = self.ctx.params['service']
        use_key = self.ctx.params['use_key']
        use_phrase = self.ctx.params['use_phrase']
        if configuration is None:
            configuration = self.get_config()
        service_keys_on_commandline = {
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
                for k in service_keys_on_commandline
                if (v := self.ctx.params.get(k)) is not None
            },
            cast(
                'dict[str, Any]',
                configuration['services'].get(service, {}) if service else {},
            ),
            cast('dict[str, Any]', configuration.get('global', {})),
        )
        if not service and not empty_service_permitted:
            err_msg = _msg.TranslatedString(
                _msg.ErrMsgTemplate.SERVICE_REQUIRED,
                service_metavar=_msg.TranslatedString(
                    _msg.Label.VAULT_METAVAR_SERVICE
                ),
            )
            raise click.UsageError(str(err_msg))
        if use_key:
            try:
                settings.maps[0]['key'] = base64.standard_b64encode(
                    cli_helpers.select_ssh_key(ctx=self.ctx)
                ).decode('ASCII')
            except IndexError:
                self.err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.USER_ABORTED_SSH_KEY_SELECTION
                    ),
                )
            except KeyError:
                self.err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.NO_SSH_AGENT_FOUND
                    ),
                )
            except LookupError:
                self.err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.NO_SUITABLE_SSH_KEYS,
                        PROG_NAME=PROG_NAME,
                    )
                )
            except NotImplementedError:
                self.err(_msg.TranslatedString(_msg.ErrMsgTemplate.NO_AF_UNIX))
            except OSError as exc:
                self.err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.CANNOT_CONNECT_TO_AGENT,
                        error=exc.strerror,
                        filename=exc.filename,
                    ).maybe_without_filename(),
                )
            except ssh_agent.SSHAgentFailedError as exc:
                self.err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.AGENT_REFUSED_LIST_KEYS
                    ),
                    exc_info=exc,
                )
            except RuntimeError as exc:
                self.err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.CANNOT_UNDERSTAND_AGENT
                    ),
                    exc_info=exc,
                )
        elif use_phrase:
            maybe_phrase = cli_helpers.prompt_for_passphrase()
            if not maybe_phrase:
                self.err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.USER_ABORTED_PASSPHRASE
                    )
                )
            else:
                settings.maps[0]['phrase'] = maybe_phrase
        return settings

    def run_op_store_config_only(self) -> None:  # noqa: C901,PLR0912,PLR0914,PLR0915
        """Update the stored vault configuration.

        Depending on the presence or the absence of a service name,
        update either the service-specific settings, or the global
        settings.  (An empty service name is respected, i.e., updates
        the former.)

        Respect the `--unset=SETTING` option to unset the named
        settings, and the `--notes` option to edit notes interactively
        in a spawned text editor.  Issue multiple warnings, if
        appropriate, e.g. for Unicode normalization issues with stored
        passphrases or conflicting stored passphrases and keys.  Respect
        the `--overwrite-config` and `--merge-config` options when
        writing the imported configuration to disk, and the
        `--modern-editor-interface` and
        `--vault-legacy-editor-interface` options when editing notes.

        Raises:
            click.UsageError:
                The user requested that the same setting be both unset
                and set.

        """
        service = self.ctx.params['service']
        use_key = self.ctx.params['use_key']
        use_phrase = self.ctx.params['use_phrase']
        unset_settings = self.ctx.params['unset_settings']
        overwrite_config = self.ctx.params['overwrite_config']
        edit_notes = self.ctx.params['edit_notes']
        modern_editor_interface = self.ctx.params['modern_editor_interface']
        configuration = self.get_config()
        user_config = self.get_user_config()
        settings = self.run_subop_query_phrase_or_key_change(
            configuration=configuration, empty_service_permitted=True
        )
        overrides = settings.maps[0]
        view: collections.ChainMap[str, Any]
        view = (
            collections.ChainMap(*settings.maps[:2])
            if service
            else collections.ChainMap(settings.maps[0], settings.maps[2])
        )
        if use_key:
            view['key'] = overrides['key']
        elif use_phrase:
            view['phrase'] = overrides['phrase']
            try:
                cli_helpers.check_for_misleading_passphrase(
                    ('services', service) if service else ('global',),
                    overrides,
                    main_config=user_config,
                    ctx=self.ctx,
                )
            except AssertionError as exc:
                self.err(
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
                self.warning(w_msg)
        if not view.maps[0] and not unset_settings and not edit_notes:
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
        if not cli_helpers.is_completable_item(service):
            self.warning(
                _msg.TranslatedString(
                    _msg.WarnMsgTemplate.SERVICE_NAME_INCOMPLETABLE,
                    service=service,
                ),
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
        if edit_notes:
            assert service is not None
            notes_instructions = _msg.TranslatedString(
                _msg.Label.DERIVEPASSPHRASE_VAULT_NOTES_INSTRUCTION_TEXT
            )
            notes_marker = _msg.TranslatedString(
                _msg.Label.DERIVEPASSPHRASE_VAULT_NOTES_MARKER
            )
            notes_legacy_instructions = _msg.TranslatedString(
                _msg.Label.DERIVEPASSPHRASE_VAULT_NOTES_LEGACY_INSTRUCTION_TEXT
            )
            old_notes_value = subtree.get('notes', '')
            if modern_editor_interface:
                text = '\n'.join([
                    str(notes_instructions),
                    str(notes_marker),
                    old_notes_value,
                ])
            else:
                text = old_notes_value or str(notes_legacy_instructions)
            notes_value = click.edit(text=text, require_save=False)
            assert notes_value is not None
            if (
                not modern_editor_interface
                and notes_value.strip() != old_notes_value.strip()
            ):
                backup_file = cli_helpers.config_filename(
                    subsystem='notes backup'
                )
                backup_file.write_text(old_notes_value, encoding='UTF-8')
                self.warning(
                    _msg.TranslatedString(
                        _msg.WarnMsgTemplate.LEGACY_EDITOR_INTERFACE_NOTES_BACKUP,
                        filename=str(backup_file),
                    ),
                )
                subtree['notes'] = notes_value.strip()
            elif (
                modern_editor_interface and notes_value.strip() != text.strip()
            ):
                notes_lines = collections.deque(
                    notes_value.splitlines(keepends=True)
                )
                while notes_lines:
                    line = notes_lines.popleft()
                    if line.startswith(str(notes_marker)):
                        notes_value = ''.join(notes_lines)
                        break
                else:
                    if not notes_value.strip():
                        self.err(
                            _msg.TranslatedString(
                                _msg.ErrMsgTemplate.USER_ABORTED_EDIT
                            )
                        )
                subtree['notes'] = notes_value.strip()
        self.put_config(configuration)

    def run_op_derive_passphrase(self) -> None:
        """Derive a passphrase.

        Derive a service passphrase using the effective settings from
        both the command-line and the stored configuration.  If any
        service notes are stored for this service, print them as well.

        (An empty service name is permitted, though discouraged for
        compatibility reasons.)

        Issue a warning (if appropriate) for Unicode normalization
        issues with the interactive passphrase.  Respect the
        `--print-notes-before` and `--print-notes-after` options when
        printing notes.

        Raises:
            click.UsageError:
                No master passphrase or master SSH key was given on both
                the command-line and in the vault configuration on disk.
        """
        service = self.ctx.params['service']
        use_key = self.ctx.params['use_key']
        use_phrase = self.ctx.params['use_phrase']
        print_notes_before = self.ctx.params['print_notes_before']
        user_config = self.get_user_config()
        settings = self.run_subop_query_phrase_or_key_change(
            empty_service_permitted=False
        )
        if use_phrase:
            try:
                cli_helpers.check_for_misleading_passphrase(
                    cli_helpers.ORIGIN.INTERACTIVE,
                    {'phrase': settings['phrase']},
                    main_config=user_config,
                    ctx=self.ctx,
                )
            except AssertionError as exc:
                self.err(
                    _msg.TranslatedString(
                        _msg.ErrMsgTemplate.INVALID_USER_CONFIG,
                        error=exc,
                        filename=None,
                    ).maybe_without_filename(),
                )
        phrase: str | bytes
        overrides = cast('dict[str, int | str]', settings.maps[0])
        # If either --key or --phrase are given, use that setting.
        # Otherwise, if both key and phrase are set in the config,
        # use the key.  Otherwise, if only one of key and phrase is
        # set in the config, use that one.  In all these above
        # cases, set the phrase via vault.Vault.phrase_from_key if
        # a key is given.  Finally, if nothing is set, error out.
        if use_key:
            phrase = cli_helpers.key_to_phrase(
                cast('str', overrides['key']), error_callback=self.err
            )
        elif use_phrase:
            phrase = cast('str', overrides['phrase'])
        elif settings.get('key'):
            phrase = cli_helpers.key_to_phrase(
                cast('str', settings['key']), error_callback=self.err
            )
        elif settings.get('phrase'):
            phrase = cast('str', settings['phrase'])
        else:
            err_msg = _msg.TranslatedString(
                _msg.ErrMsgTemplate.NO_KEY_OR_PHRASE
            )
            raise click.UsageError(str(err_msg))
        overrides.pop('key', '')
        overrides.pop('phrase', '')
        assert service is not None
        vault_service_keys = {
            'length',
            'repeat',
            'lower',
            'upper',
            'number',
            'space',
            'dash',
            'symbol',
        }
        kwargs = {
            cast('str', k): cast('int', settings[k])
            for k in vault_service_keys
            if k in settings
        }
        result = vault.Vault(phrase=phrase, **kwargs).generate(service)
        service_notes = cast('str', settings.get('notes', '')).strip()
        if print_notes_before and service_notes.strip():
            click.echo(f'{service_notes}\n', err=True, color=self.ctx.color)
        click.echo(result.decode('ASCII'), color=self.ctx.color)
        if not print_notes_before and service_notes.strip():
            click.echo(f'\n{service_notes}\n', err=True, color=self.ctx.color)


@derivepassphrase.command(
    'vault',
    context_settings={'help_option_names': ['-h', '--help']},
    cls=cli_machinery.CommandWithHelpGroups,
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
    cls=cli_machinery.PassphraseGenerationOption,
)
@click.option(
    '-k',
    '--key',
    'use_key',
    is_flag=True,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_KEY_HELP_TEXT
    ),
    cls=cli_machinery.PassphraseGenerationOption,
)
@click.option(
    '-l',
    '--length',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=cli_machinery.validate_length,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_LENGTH_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=cli_machinery.PassphraseGenerationOption,
)
@click.option(
    '-r',
    '--repeat',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=cli_machinery.validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_REPEAT_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=cli_machinery.PassphraseGenerationOption,
)
@click.option(
    '--lower',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=cli_machinery.validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_LOWER_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=cli_machinery.PassphraseGenerationOption,
)
@click.option(
    '--upper',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=cli_machinery.validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_UPPER_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=cli_machinery.PassphraseGenerationOption,
)
@click.option(
    '--number',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=cli_machinery.validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_NUMBER_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=cli_machinery.PassphraseGenerationOption,
)
@click.option(
    '--space',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=cli_machinery.validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_SPACE_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=cli_machinery.PassphraseGenerationOption,
)
@click.option(
    '--dash',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=cli_machinery.validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_DASH_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=cli_machinery.PassphraseGenerationOption,
)
@click.option(
    '--symbol',
    metavar=_msg.TranslatedString(
        _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
    ),
    callback=cli_machinery.validate_occurrence_constraint,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_SYMBOL_HELP_TEXT,
        metavar=_msg.TranslatedString(
            _msg.Label.PASSPHRASE_GENERATION_METAVAR_NUMBER
        ),
    ),
    cls=cli_machinery.PassphraseGenerationOption,
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
    cls=cli_machinery.ConfigurationOption,
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
    cls=cli_machinery.ConfigurationOption,
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
    cls=cli_machinery.ConfigurationOption,
)
@click.option(
    '--delete-globals',
    is_flag=True,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_DELETE_GLOBALS_HELP_TEXT,
    ),
    cls=cli_machinery.ConfigurationOption,
)
@click.option(
    '-X',
    '--clear',
    'clear_all_settings',
    is_flag=True,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_DELETE_ALL_HELP_TEXT,
    ),
    cls=cli_machinery.ConfigurationOption,
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
    cls=cli_machinery.StorageManagementOption,
    shell_complete=cli_helpers.shell_complete_path,
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
    cls=cli_machinery.StorageManagementOption,
    shell_complete=cli_helpers.shell_complete_path,
)
@click.option(
    '--overwrite-existing/--merge-existing',
    'overwrite_config',
    default=False,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_OVERWRITE_HELP_TEXT
    ),
    cls=cli_machinery.CompatibilityOption,
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
        'notes',
    ]),
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_UNSET_HELP_TEXT
    ),
    cls=cli_machinery.CompatibilityOption,
)
@click.option(
    '--export-as',
    type=click.Choice(['json', 'sh']),
    default='json',
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_EXPORT_AS_HELP_TEXT
    ),
    cls=cli_machinery.CompatibilityOption,
)
@click.option(
    '--modern-editor-interface/--vault-legacy-editor-interface',
    'modern_editor_interface',
    default=False,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_EDITOR_INTERFACE_HELP_TEXT
    ),
    cls=cli_machinery.CompatibilityOption,
)
@click.option(
    '--print-notes-before/--print-notes-after',
    'print_notes_before',
    default=False,
    help=_msg.TranslatedString(
        _msg.Label.DERIVEPASSPHRASE_VAULT_PRINT_NOTES_BEFORE_HELP_TEXT,
        service_metavar=_msg.TranslatedString(
            _msg.Label.VAULT_METAVAR_SERVICE
        ),
    ),
    cls=cli_machinery.CompatibilityOption,
)
@cli_machinery.version_option(cli_machinery.vault_version_option_callback)
@cli_machinery.color_forcing_pseudo_option
@cli_machinery.standard_logging_options
@click.argument(
    'service',
    metavar=_msg.TranslatedString(_msg.Label.VAULT_METAVAR_SERVICE),
    required=False,
    default=None,
    shell_complete=cli_helpers.shell_complete_service,
)
@click.pass_context
def derivepassphrase_vault(
    ctx: click.Context,
    /,
    **_kwargs: Any,  # noqa: ANN401
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
        service (str | None):
            A service name.  Required, unless operating on global
            settings or importing/exporting settings.
        use_phrase (bool):
            Command-line argument `-p`/`--phrase`.  If given, query the
            user for a passphrase instead of an SSH key.
        use_key (bool):
            Command-line argument `-k`/`--key`.  If given, query the
            user for an SSH key instead of a passphrase.
        length (int | None):
            Command-line argument `-l`/`--length`.  Override the default
            length of the generated passphrase.
        repeat (int | None):
            Command-line argument `-r`/`--repeat`.  Override the default
            repetition limit if positive, or disable the repetition
            limit if 0.
        lower (int | None):
            Command-line argument `--lower`.  Require a given amount of
            ASCII lowercase characters if positive, else forbid ASCII
            lowercase characters if 0.
        upper (int | None):
            Command-line argument `--upper`.  Same as `lower`, but for
            ASCII uppercase characters.
        number (int | None):
            Command-line argument `--number`.  Same as `lower`, but for
            ASCII digits.
        space (int | None):
            Command-line argument `--space`.  Same as `lower`, but for
            the space character.
        dash (int | None):
            Command-line argument `--dash`.  Same as `lower`, but for
            the hyphen-minus and underscore characters.
        symbol (int | None):
            Command-line argument `--symbol`.  Same as `lower`, but for
            all other ASCII printable characters except lowercase
            characters, uppercase characters, digits, space and
            backquote.
        edit_notes (bool):
            Command-line argument `-n`/`--notes`.  If given, spawn an
            editor to edit notes for `service`.
        store_config_only (bool):
            Command-line argument `-c`/`--config`.  If given, saves the
            other given settings (`--key`, ..., `--symbol`) to the
            configuration file, either specifically for `service` or as
            global settings.
        delete_service_settings (bool):
            Command-line argument `-x`/`--delete`.  If given, removes
            the settings for `service` from the configuration file.
        delete_globals (bool):
            Command-line argument `--delete-globals`.  If given, removes
            the global settings from the configuration file.
        clear_all_settings (bool):
            Command-line argument `-X`/`--clear`.  If given, removes all
            settings from the configuration file.
        export_settings (TextIO | os.PathLike[str] | None):
            Command-line argument `-e`/`--export`.  If a file object,
            then it must be open for writing and accept `str` inputs.
            Otherwise, a filename to open for writing.  Using `-` for
            standard output is supported.
        import_settings (TextIO | os.PathLike[str] | None):
            Command-line argument `-i`/`--import`.  If a file object, it
            must be open for reading and yield `str` values.  Otherwise,
            a filename to open for reading.  Using `-` for standard
            input is supported.
        overwrite_config (bool):
            Command-line arguments `--overwrite-existing` (True) and
            `--merge-existing` (False).  Controls whether config saving
            and config importing overwrite existing configurations, or
            merge them section-wise instead.
        unset_settings (Sequence[str]):
            Command-line argument `--unset`.  If given together with
            `--config`, unsets the specified settings (in addition to
            any other changes requested).
        export_as (Literal['json', 'sh']):
            Command-line argument `--export-as`.  If given together with
            `--export`, selects the format to export the current
            configuration as: JSON ("json", default) or POSIX sh ("sh").
        modern_editor_interface (bool):
            Command-line arguments `--modern-editor-interface` (True)
            and `--vault-legacy-editor-interface` (False).  Controls
            whether editing notes uses a modern editor interface
            (supporting comments and aborting) or a vault(1)-compatible
            legacy editor interface (WYSIWYG notes contents).
        print_notes_before (bool):
            Command-line arguments `--print-notes-before` (True) and
            `--print-notes-after` (False).  Controls whether the service
            notes (if any) are printed before the passphrase, or after.

    """
    vault_context = _VaultContext(ctx)
    vault_context.validate_command_line()
    vault_context.dispatch_op()


if __name__ == '__main__':
    derivepassphrase()
