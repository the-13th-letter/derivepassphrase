# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Command-line interface for derivepassphrase.

"""

from __future__ import annotations

import inspect
import json
import pathlib
from typing import Any, TextIO

import click
import derivepassphrase as dpp
from derivepassphrase import types as dpp_types

__author__ = dpp.__author__
__version__ = dpp.__version__

__all__ = ('derivepassphrase',)

prog_name = 'derivepassphrase'


def _config_filename() -> str | bytes | pathlib.Path:
    """Return the filename of the configuration file.

    The file is currently named `settings.json`, located within the
    configuration directory as determined by the `DERIVEPASSPHRASE_PATH`
    environment variable, or by [`click.get_app_dir`][] in POSIX
    mode.

    """
    path: str | bytes | pathlib.Path
    path = (os.getenv(prog_name.upper() + '_PATH')
            or click.get_app_dir(prog_name, force_posix=True))
    return os.path.join(path, 'settings.json')


def _load_config() -> dpp_types.VaultConfig:
    """Load a vault(1)-compatible config from the application directory.

    The filename is obtained via
    [`derivepassphrase.cli._config_filename`][].  This must be an
    unencrypted JSON file.

    Returns:
        The vault settings.  See
        [`derivepassphrase.types.VaultConfig`][] for details.

    Raises:
        OSError:
            There was an OS error accessing the file.
        ValueError:
            The data loaded from the file is not a vault(1)-compatible
            config.

    """
    filename = _config_filename()
    with open(filename, 'rb') as fileobj:
        data = json.load(fileobj)
    if not dpp_types.is_vault_config(data):
        raise ValueError('Invalid vault config')
    return data


def _save_config(config: dpp_types.VaultConfig, /) -> None:
    """Save a vault(1)-compatbile config to the application directory.

    The filename is obtained via
    [`derivepassphrase.cli._config_filename`][].  The config will be
    stored as an unencrypted JSON file.

    Args:
        config:
            vault configuration to save.

    Raises:
        OSError:
            There was an OS error accessing or writing the file.
        ValueError:
            The data cannot be stored as a vault(1)-compatible config.

    """
    if not dpp_types.is_vault_config(config):
        raise ValueError('Invalid vault config')
    filename = _config_filename()
    with open(filename, 'wt', encoding='UTF-8') as fileobj:
        json.dump(config, fileobj)


class OptionGroupOption(click.Option):
    """A [`click.Option`][] with an associated group name and group epilog.

    Used by [`derivepassphrase.cli.CommandWithHelpGroups`][] to print
    help sections.  Each subclass contains its own group name and
    epilog.

    Attributes:
        option_group_name:
            The name of the option group.  Used as a heading on the help
            text for options in this section.
        epilog:
            An epilog to print after listing the options in this
            section.

    """
    option_group_name: str = ''
    epilog: str = ''

    def __init__(self, *args, **kwargs):  # type: ignore
        if self.__class__ == __class__:
            raise NotImplementedError()
        return super().__init__(*args, **kwargs)


class CommandWithHelpGroups(click.Command):
    """A [`click.Command`][] with support for help/option groups.

    Inspired by [a comment on `pallets/click#373`][CLICK_ISSUE], and
    further modified to support group epilogs.

    [CLICK_ISSUE]: https://github.com/pallets/click/issues/373#issuecomment-515293746

    """

    def format_options(
        self, ctx: click.Context, formatter: click.HelpFormatter,
    ) -> None:
        r"""Format options on the help listing, grouped into sections.

        As part of the `--help` listing, list all options, but grouped
        into sections according to the concrete [`click.Option`][]
        subclass being used.  If the option is an instance of some
        subclass `X` of [`derivepassphrase.cli.OptionGroupOption`][],
        then the section heading and the epilog is taken from
        `X.option_group_name` and `X.epilog`; otherwise, the section
        heading is "Options" (or "Other options" if there are other
        option groups) and the epilog is empty.

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
        default_group_name = ('Other Options' if len(default_group) > 1
                              else 'Options')
        help_records[default_group_name] = default_group
        for group_name, records in help_records.items():
            with formatter.section(group_name):
                formatter.write_dl(records)
            epilog = inspect.cleandoc(epilogs.get(group_name, ''))
            if epilog:
                formatter.write_paragraph()
                with formatter.indentation():
                    formatter.write_text(epilog)


# Concrete option groups used by this command-line interface.
class PasswordGenerationOption(OptionGroupOption):
    """Password generation options for the CLI."""
    option_group_name = 'Password generation'
    epilog = '''
        Use NUMBER=0, e.g. "--symbol 0", to exclude a character type
        from the output.
    '''


class ConfigurationOption(OptionGroupOption):
    """Configuration options for the CLI."""
    option_group_name = 'Configuration'
    epilog = '''
        Use $VISUAL or $EDITOR to configure the spawned editor.
    '''


class StorageManagementOption(OptionGroupOption):
    """Storage management options for the CLI."""
    option_group_name = 'Storage management'
    epilog = '''
        Using "-" as PATH for standard input/standard output is
        supported.
    '''

def _validate_occurrence_constraint(
    ctx: click.Context, param: click.Parameter, value: Any,
) -> int | None:
    """Check that the occurrence constraint is valid (int, 0 or larger)."""
    if value is None:
        return value
    if isinstance(value, int):
        int_value = value
    else:
        try:
            int_value = int(value, 10)
        except ValueError as e:
            raise click.BadParameter('not an integer') from e
    if int_value < 0:
        raise click.BadParameter('not a non-negative integer')
    return int_value


def _validate_length(
    ctx: click.Context, param: click.Parameter, value: Any,
) -> int | None:
    """Check that the length is valid (int, 1 or larger)."""
    if value is None:
        return value
    if isinstance(value, int):
        int_value = value
    else:
        try:
            int_value = int(value, 10)
        except ValueError as e:
            raise click.BadParameter('not an integer') from e
    if int_value < 1:
        raise click.BadParameter('not a positive integer')
    return int_value

@click.command(
    context_settings={"help_option_names": ["-h", "--help"]},
    cls=CommandWithHelpGroups,
    epilog='''
        WARNING: There is NO WAY to retrieve the generated passphrases
        if the master passphrase, the SSH key, or the exact passphrase
        settings are lost, short of trying out all possible
        combinations.  You are STRONGLY advised to keep independent
        backups of the settings and the SSH key, if any.
    ''',
)
@click.option('-p', '--phrase', 'use_phrase', is_flag=True,
              help='prompts you for your passphrase',
              cls=PasswordGenerationOption)
@click.option('-k', '--key', 'use_key', is_flag=True,
              help='uses your SSH private key to generate passwords',
              cls=PasswordGenerationOption)
@click.option('-l', '--length', metavar='NUMBER',
              callback=_validate_length,
              help='emits password of length NUMBER',
              cls=PasswordGenerationOption)
@click.option('-r', '--repeat', metavar='NUMBER',
              callback=_validate_occurrence_constraint,
              help='allows maximum of NUMBER repeated adjacent chars',
              cls=PasswordGenerationOption)
@click.option('--lower', metavar='NUMBER',
              callback=_validate_occurrence_constraint,
              help='includes at least NUMBER lowercase letters',
              cls=PasswordGenerationOption)
@click.option('--upper', metavar='NUMBER',
              callback=_validate_occurrence_constraint,
              help='includes at least NUMBER uppercase letters',
              cls=PasswordGenerationOption)
@click.option('--number', metavar='NUMBER',
              callback=_validate_occurrence_constraint,
              help='includes at least NUMBER digits',
              cls=PasswordGenerationOption)
@click.option('--space', metavar='NUMBER',
              callback=_validate_occurrence_constraint,
              help='includes at least NUMBER spaces',
              cls=PasswordGenerationOption)
@click.option('--dash', metavar='NUMBER',
              callback=_validate_occurrence_constraint,
              help='includes at least NUMBER "-" or "_"',
              cls=PasswordGenerationOption)
@click.option('--symbol', metavar='NUMBER',
              callback=_validate_occurrence_constraint,
              help='includes at least NUMBER symbol chars',
              cls=PasswordGenerationOption)
@click.option('-n', '--notes', 'edit_notes', is_flag=True,
              help='spawn an editor to edit notes for SERVICE',
              cls=ConfigurationOption)
@click.option('-c', '--config', 'store_config_only', is_flag=True,
              help='saves the given settings for SERVICE or global',
              cls=ConfigurationOption)
@click.option('-x', '--delete', 'delete_service_settings', is_flag=True,
              help='deletes settings for SERVICE',
              cls=ConfigurationOption)
@click.option('--delete-globals', is_flag=True,
              help='deletes the global shared settings',
              cls=ConfigurationOption)
@click.option('-X', '--clear', 'clear_all_settings', is_flag=True,
              help='deletes all settings',
              cls=ConfigurationOption)
@click.option('-e', '--export', 'export_settings', metavar='PATH',
              type=click.Path(file_okay=True, allow_dash=True, exists=False),
              help='export all saved settings into file PATH',
              cls=StorageManagementOption)
@click.option('-i', '--import', 'import_settings', metavar='PATH',
              type=click.Path(file_okay=True, allow_dash=True, exists=False),
              help='import saved settings from file PATH',
              cls=StorageManagementOption)
@click.version_option(version=dpp.__version__, prog_name=prog_name)
@click.argument('service', required=False)
@click.pass_context
def derivepassphrase(
    ctx: click.Context, /, *,
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
) -> None:
    """Derive a strong passphrase, deterministically, from a master secret.

    Using a master passphrase or a master SSH key, derive a strong
    passphrase for SERVICE, deterministically, subject to length,
    character and character repetition constraints.  The service name
    and constraints themselves need not be kept secret; the latter are
    usually stored in a world-readable file.

    If operating on global settings, or importing/exporting settings,
    then SERVICE must be omitted.  Otherwise it is required.\f

    This is a [`click`][CLICK]-powered command-line interface function,
    and not intended for programmatic use.  Call with arguments
    `['--help']` to see full documentation of the interface.  (See also
    [`click.testing.CliRunner`][] for controlled, programmatic
    invocation.)

    [CLICK]: https://click.palletsprojects.com/

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
            Command-line argument `--number`.  Same as `lower`, but for
            the space character.
        dash:
            Command-line argument `--number`.  Same as `lower`, but for
            the hyphen-minus and underscore characters.
        symbol:
            Command-line argument `--number`.  Same as `lower`, but for
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

    """

    options_in_group: dict[type[click.Option], list[click.Option]] = {}
    params_by_str: dict[str, click.Parameter] = {}
    for param in ctx.command.params:
        if isinstance(param, click.Option):
            group: type[click.Option]
            match param:
                case PasswordGenerationOption():
                    group = PasswordGenerationOption
                case ConfigurationOption():
                    group = ConfigurationOption
                case StorageManagementOption():
                    group = StorageManagementOption
                case OptionGroupOption():
                    raise AssertionError(
                        f'Unknown option group for {param!r}')
                case _:
                    group = click.Option
            options_in_group.setdefault(group, []).append(param)
        params_by_str[param.human_readable_name] = param
        for name in param.opts + param.secondary_opts:
            params_by_str[name] = param

    def is_param_set(param: click.Parameter):
        return bool(ctx.params.get(param.human_readable_name))

    def check_incompatible_options(
        param: click.Parameter | str, *incompatible: click.Parameter | str,
    ) -> None:
        if isinstance(param, str):
            param = params_by_str[param]
        assert isinstance(param, click.Parameter)
        if not is_param_set(param):
            return
        for other in incompatible:
            if isinstance(other, str):
                other = params_by_str[other]
            assert isinstance(other, click.Parameter)
            if other != param and is_param_set(other):
                opt_str = param.opts[0]
                other_str = other.opts[0]
                raise click.BadOptionUsage(
                    opt_str, f'mutually exclusive with {other_str}', ctx=ctx)

    def get_config() -> dpp_types.VaultConfig:
        try:
            return _load_config()
        except FileNotFoundError:
            return {'services': {}}
        except Exception as e:
            ctx.fail(f'cannot load config: {e}')

    configuration: dpp_types.VaultConfig

    check_incompatible_options('--phrase', '--key')
    for group in (ConfigurationOption, StorageManagementOption):
        for opt in options_in_group[group]:
            if opt != params_by_str['--config']:
                check_incompatible_options(
                    opt, *options_in_group[PasswordGenerationOption])

    for group in (ConfigurationOption, StorageManagementOption):
        for opt in options_in_group[group]:
            check_incompatible_options(
                opt, *options_in_group[ConfigurationOption],
                *options_in_group[StorageManagementOption])
    sv_options = (options_in_group[PasswordGenerationOption] +
                  [params_by_str['--notes'], params_by_str['--delete']])
    sv_options.remove(params_by_str['--key'])
    sv_options.remove(params_by_str['--phrase'])
    for param in sv_options:
        if is_param_set(param) and not service:
            opt_str = param.opts[0]
            raise click.UsageError(f'{opt_str} requires a SERVICE')
    for param in [params_by_str['--key'], params_by_str['--phrase']]:
        if (
            is_param_set(param)
            and not (service or is_param_set(params_by_str['--config']))
        ):
            opt_str = param.opts[0]
            raise click.UsageError(f'{opt_str} requires a SERVICE or --config')
    no_sv_options = [params_by_str['--delete-globals'],
                     params_by_str['--clear'],
                     *options_in_group[StorageManagementOption]]
    for param in no_sv_options:
        if is_param_set(param) and service:
            opt_str = param.opts[0]
            raise click.UsageError(
                f'{opt_str} does not take a SERVICE argument')
    #if kwargs['length'] is None:
    #    kwargs['length'] = dpp.Vault.__init__.__kwdefaults__['length']
    #if kwargs['repeat'] is None:
    #    kwargs['repeat'] = dpp.Vault.__init__.__kwdefaults__['repeat']
    click.echo(repr(ctx.params))


if __name__ == '__main__':
    derivepassphrase()
