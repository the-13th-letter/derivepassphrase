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


# Implement help text groups. Inspired by
# https://github.com/pallets/click/issues/373#issuecomment-515293746 and
# modified to support group epilogs as well.
class OptionGroupOption(click.Option):
    option_group_name = ''
    epilog = ''

class CommandWithHelpGroups(click.Command):
    def format_options(
        self, ctx: click.Context, formatter: click.HelpFormatter,
    ) -> None:
        help_records: dict[str, list[tuple[str, str]]] = {}
        epilogs: dict[str, str] = {}
        params = self.params[:]
        if (help_opt := self.get_help_option(ctx)) and help_opt not in params:
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
    option_group_name = 'Password generation'
    epilog = 'Use NUMBER=0, e.g. "--symbol 0", to exclude a character type from the output'

class ConfigurationOption(OptionGroupOption):
    option_group_name = 'Configuration'
    epilog = 'Use $VISUAL or $EDITOR to configure the spawned editor.'

class StorageManagementOption(OptionGroupOption):
    option_group_name = 'Storage management'
    epilog = 'Using "-" as PATH for standard input/standard output is supported.'

def validate_occurrence_constraint(
    ctx: click.Context, param: click.Parameter, value: Any,
) -> int | None:
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

def validate_length(
    ctx: click.Context, param: click.Parameter, value: Any,
) -> int | None:
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
@click.option('-p', '--phrase', is_flag=True,
              help='prompts you for your passphrase',
              cls=PasswordGenerationOption)
@click.option('-k', '--key', is_flag=True,
              help='uses your SSH private key to generate passwords',
              cls=PasswordGenerationOption)
@click.option('-l', '--length', metavar='NUMBER', callback=validate_length,
              help='emits password of length NUMBER',
              cls=PasswordGenerationOption)
@click.option('-r', '--repeat', metavar='NUMBER',
              callback=validate_occurrence_constraint,
              help='allows maximum of NUMBER repeated adjacent chars',
              cls=PasswordGenerationOption)
@click.option('--lower', metavar='NUMBER',
              callback=validate_occurrence_constraint,
              help='includes at least NUMBER lowercase letters',
              cls=PasswordGenerationOption)
@click.option('--upper', metavar='NUMBER',
              callback=validate_occurrence_constraint,
              help='includes at least NUMBER uppercase letters',
              cls=PasswordGenerationOption)
@click.option('--number', metavar='NUMBER',
              callback=validate_occurrence_constraint,
              help='includes at least NUMBER digits',
              cls=PasswordGenerationOption)
@click.option('--space', metavar='NUMBER',
              callback=validate_occurrence_constraint,
              help='includes at least NUMBER spaces',
              cls=PasswordGenerationOption)
@click.option('--dash', metavar='NUMBER',
              callback=validate_occurrence_constraint,
              help='includes at least NUMBER "-" or "_"',
              cls=PasswordGenerationOption)
@click.option('--symbol', metavar='NUMBER',
              callback=validate_occurrence_constraint,
              help='includes at least NUMBER symbol chars',
              cls=PasswordGenerationOption)
@click.option('-n', '--notes', is_flag=True,
              help='spawn an editor to edit notes for SERVICE',
              cls=ConfigurationOption)
@click.option('-c', '--config', is_flag=True,
              help='saves the given settings for SERVICE or global',
              cls=ConfigurationOption)
@click.option('-x', '--delete', is_flag=True,
              help='deletes settings for SERVICE',
              cls=ConfigurationOption)
@click.option('--delete-globals', is_flag=True,
              help='deletes the global shared settings',
              cls=ConfigurationOption)
@click.option('-X', '--clear', is_flag=True,
              help='deletes all settings',
              cls=ConfigurationOption)
@click.option('-e', '--export', metavar='PATH', type=click.File('wt'),
              help='export all saved settings into file PATH',
              cls=StorageManagementOption)
@click.option('-i', '--import', metavar='PATH', type=click.File('rt'),
              help='import saved settings from file PATH',
              cls=StorageManagementOption)
@click.version_option(version=dpp.__version__, prog_name=prog_name)
@click.argument('service', required=False)
@click.pass_context
def derivepassphrase(
    ctx: click.Context, service: str | None = None, **kwargs: Any,
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
    `['--help']` to see full documentation of the interface.

    [CLICK]: https://click.palletsprojects.com/

    Parameters:
        ctx (click.Context):
            The `click` context.

    Other Parameters:
        service (str | None):
            A service name.  Required, unless operating on global
            settings or importing/exporting settings.
        phrase (bool):
            Command-line argument `-p`/`--phrase`.  If given, query the
            user for a passphrase instead of an SSH key.
        key (bool):
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
            Command-line argument `--number`.  Same as `lower`, but for
            the space character.
        dash (int | None):
            Command-line argument `--number`.  Same as `lower`, but for
            the hyphen-minus and underscore characters.
        symbol (int | None):
            Command-line argument `--number`.  Same as `lower`, but for
            all other ASCII printable characters (except backquote).
        notes (bool):
            Command-line argument `-n`/`--notes`.  If given, spawn an
            editor to edit notes for `service`.
        config (bool):
            Command-line argument `-c`/`--config`.  If given, saves the
            other given settings (`--key`, ..., `--symbol`) to the
            configuration file, either specifically for `service` or as
            global settings.
        delete (bool):
            Command-line argument `-x`/`--delete`.  If given, removes
            the settings for `service` from the configuration file.
        delete_globals (bool):
            Command-line argument `--delete-globals`.  If given, removes
            the global settings from the configuration file.
        clear (bool):
            Command-line argument `-X`/`--clear`.  If given, removes all
            settings from the configuration file.
        export (TextIO | click.utils.LazyFile | None):
            Command-line argument `-e`/`--export`.  If given, exports
            the settings to the given file object (or
            a `click.utils.LazyFile` instance that eventually supplies
            such a file object), which must be open for writing and
            accept `str` inputs.
        import (TextIO | click.utils.LazyFile | None):
            Command-line argument `-i`/`--import`.  If given, imports
            the settings from the given file object (or
            a `click.utils.LazyFile` instance that eventually supplies
            such a file object), which must be open for reading and
            yield `str` values.

    """
    options: dict[type[click.Option], list[str]] = {}
    for param in ctx.command.params:
        if isinstance(param, click.Option):
            param_name = param.human_readable_name
            group: type[click.Option]
            if isinstance(param, PasswordGenerationOption):
                group = PasswordGenerationOption
            elif isinstance(param, ConfigurationOption):
                group = ConfigurationOption
            elif isinstance(param, StorageManagementOption):
                group = StorageManagementOption
            elif isinstance(param, OptionGroupOption):
                raise AssertionError(f'Unknown option group for {param!r}')
            else:
                group = click.Option
            options.setdefault(group, []).append(param_name)
    def check_incompatible_options(
        param_name: str, *incompatible: str
    ) -> None:
        parsed_params = ctx.params
        if parsed_params.get(param_name) is None:
            return
        for other in incompatible:
            if other != param_name and parsed_params.get(other) is not None:
                param_name = param_name.replace('_', '-')
                other = other.replace('_', '-')
                raise click.UsageError(
                     f'--{param_name} and --{other} are mutually exclusive')
    check_incompatible_options('phrase', 'key')
    for group in (ConfigurationOption, StorageManagementOption):
        for opt in options[group]:
            if opt != 'config':
                check_incompatible_options(opt,
                                           *options[PasswordGenerationOption])
    for group in (ConfigurationOption, StorageManagementOption):
        for opt in options[group]:
            check_incompatible_options(opt,
                                       *options[ConfigurationOption],
                                       *options[StorageManagementOption])
    for opt in ['notes', 'delete']:
        if kwargs.get(opt) is not None and not service:
            opt = opt.replace('_', '-')
            raise click.UsageError(f'--{opt} requires a SERVICE')
    for opt in ['delete_globals', 'clear'] + options[StorageManagementOption]:
        if kwargs.get(opt) is not None and service:
            opt = opt.replace('_', '-')
            raise click.UsageError(
                f'--{opt} does not take a SERVICE argument')
    #if kwargs['length'] is None:
    #    kwargs['length'] = dpp.Vault.__init__.__kwdefaults__['length']
    #if kwargs['repeat'] is None:
    #    kwargs['repeat'] = dpp.Vault.__init__.__kwdefaults__['repeat']
    click.echo(repr({'service': service, **kwargs}))


if __name__ == '__main__':
    derivepassphrase()
