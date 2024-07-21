# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Command-line interface for derivepassphrase."""

from __future__ import annotations

import base64
import collections
import contextlib
import copy
import inspect
import json
import os
import socket
from typing import (
    TYPE_CHECKING,
    TextIO,
    cast,
)

import click
from typing_extensions import (
    Any,
    assert_never,
)

import derivepassphrase as dpp
import ssh_agent_client
from derivepassphrase import types as dpp_types

if TYPE_CHECKING:
    import pathlib
    from collections.abc import (
        Iterator,
        Sequence,
    )

__author__ = dpp.__author__
__version__ = dpp.__version__

__all__ = ('derivepassphrase',)

PROG_NAME = 'derivepassphrase'
KEY_DISPLAY_LENGTH = 30

# Error messages
_INVALID_VAULT_CONFIG = 'Invalid vault config'
_AGENT_COMMUNICATION_ERROR = 'Error communicating with the SSH agent'
_NO_USABLE_KEYS = 'No usable SSH keys were found'
_EMPTY_SELECTION = 'Empty selection'


def _config_filename() -> str | bytes | pathlib.Path:
    """Return the filename of the configuration file.

    The file is currently named `settings.json`, located within the
    configuration directory as determined by the `DERIVEPASSPHRASE_PATH`
    environment variable, or by [`click.get_app_dir`][] in POSIX
    mode.

    """
    path: str | bytes | pathlib.Path
    path = os.getenv(PROG_NAME.upper() + '_PATH') or click.get_app_dir(
        PROG_NAME, force_posix=True
    )
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
        raise ValueError(_INVALID_VAULT_CONFIG)
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
        raise ValueError(_INVALID_VAULT_CONFIG)
    filename = _config_filename()
    with open(filename, 'w', encoding='UTF-8') as fileobj:
        json.dump(config, fileobj)


def _get_suitable_ssh_keys(
    conn: ssh_agent_client.SSHAgentClient | socket.socket | None = None, /
) -> Iterator[ssh_agent_client.types.KeyCommentPair]:
    """Yield all SSH keys suitable for passphrase derivation.

    Suitable SSH keys are queried from the running SSH agent (see
    [`ssh_agent_client.SSHAgentClient.list_keys`][]).

    Args:
        conn:
            An optional connection hint to the SSH agent; specifically,
            an SSH agent client, or a socket connected to an SSH agent.

            If an existing SSH agent client, then this client will be
            queried for the SSH keys, and otherwise left intact.

            If a socket, then a one-shot client will be constructed
            based on the socket to query the agent, and deconstructed
            afterwards.

            If neither are given, then the agent's socket location is
            looked up in the `SSH_AUTH_SOCK` environment variable, and
            used to construct/deconstruct a one-shot client, as in the
            previous case.

    Yields:
        :
            Every SSH key from the SSH agent that is suitable for
            passphrase derivation.

    Raises:
        LookupError:
            No keys usable for passphrase derivation are loaded into the
            SSH agent.
        RuntimeError:
            There was an error communicating with the SSH agent.

    """
    client: ssh_agent_client.SSHAgentClient
    client_context: contextlib.AbstractContextManager
    match conn:
        case ssh_agent_client.SSHAgentClient():
            client = conn
            client_context = contextlib.nullcontext()
        case socket.socket() | None:
            client = ssh_agent_client.SSHAgentClient(socket=conn)
            client_context = client
        case _:  # pragma: no cover
            assert_never(conn)
            msg = f'invalid connection hint: {conn!r}'
            raise TypeError(msg)
    with client_context:
        try:
            all_key_comment_pairs = list(client.list_keys())
        except EOFError as e:  # pragma: no cover
            raise RuntimeError(_AGENT_COMMUNICATION_ERROR) from e
    suitable_keys = copy.copy(all_key_comment_pairs)
    for pair in all_key_comment_pairs:
        key, _comment = pair
        if dpp.Vault._is_suitable_ssh_key(key):  # noqa: SLF001
            yield pair
    if not suitable_keys:  # pragma: no cover
        raise IndexError(_NO_USABLE_KEYS)


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
    conn: ssh_agent_client.SSHAgentClient | socket.socket | None = None, /
) -> bytes | bytearray:
    """Interactively select an SSH key for passphrase derivation.

    Suitable SSH keys are queried from the running SSH agent (see
    [`ssh_agent_client.SSHAgentClient.list_keys`][]), then the user is
    prompted interactively (see [`click.prompt`][]) for a selection.

    Args:
        conn:
            An optional connection hint to the SSH agent; specifically,
            an SSH agent client, or a socket connected to an SSH agent.

            If an existing SSH agent client, then this client will be
            queried for the SSH keys, and otherwise left intact.

            If a socket, then a one-shot client will be constructed
            based on the socket to query the agent, and deconstructed
            afterwards.

            If neither are given, then the agent's socket location is
            looked up in the `SSH_AUTH_SOCK` environment variable, and
            used to construct/deconstruct a one-shot client, as in the
            previous case.

    Returns:
        The selected SSH key.

    Raises:
        IndexError:
            The user made an invalid or empty selection, or requested an
            abort.
        LookupError:
            No keys usable for passphrase derivation are loaded into the
            SSH agent.
        RuntimeError:
            There was an error communicating with the SSH agent.
    """
    suitable_keys = list(_get_suitable_ssh_keys(conn))
    key_listing: list[str] = []
    unstring_prefix = ssh_agent_client.SSHAgentClient.unstring_prefix
    for key, comment in suitable_keys:
        keytype = unstring_prefix(key)[0].decode('ASCII')
        key_str = base64.standard_b64encode(key).decode('ASCII')
        key_prefix = (
            key_str
            if len(key_str) < KEY_DISPLAY_LENGTH + len('...')
            else key_str[:KEY_DISPLAY_LENGTH] + '...'
        )
        comment_str = comment.decode('UTF-8', errors='replace')
        key_listing.append(f'{keytype} {key_prefix} {comment_str}')
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
    return click.prompt(
        'Passphrase', default='', hide_input=True, show_default=False, err=True
    )


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
        is an instance of some subclass `X` of
        [`derivepassphrase.cli.OptionGroupOption`][], then the section
        heading and the epilog are taken from `X.option_group_name` and
        `X.epilog`; otherwise, the section heading is "Options" (or
        "Other options" if there are other option groups) and the epilog
        is empty.

        Args:
            ctx:
                The click context.
            formatter:
                The formatter for the `--help` listing.

        Returns:
            Nothing.  Output is generated by calling appropriate methods
            on `formatter` instead.

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


def _validate_occurrence_constraint(
    ctx: click.Context,
    param: click.Parameter,
    value: Any,
) -> int | None:
    """Check that the occurrence constraint is valid (int, 0 or larger)."""
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
    value: Any,
) -> int | None:
    """Check that the length is valid (int, 1 or larger)."""
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


@click.command(
    context_settings={'help_option_names': ['-h', '--help']},
    cls=CommandWithHelpGroups,
    epilog=r"""
        WARNING: There is NO WAY to retrieve the generated passphrases
        if the master passphrase, the SSH key, or the exact passphrase
        settings are lost, short of trying out all possible
        combinations.  You are STRONGLY advised to keep independent
        backups of the settings and the SSH key, if any.

        Configuration is stored in a directory according to the
        DERIVEPASSPHRASE_PATH variable, which defaults to
        `~/.derivepassphrase` on UNIX-like systems and
        `C:\Users\<user>\AppData\Roaming\Derivepassphrase` on Windows.
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
    type=click.Path(file_okay=True, allow_dash=True, exists=False),
    help='export all saved settings into file PATH',
    cls=StorageManagementOption,
)
@click.option(
    '-i',
    '--import',
    'import_settings',
    metavar='PATH',
    type=click.Path(file_okay=True, allow_dash=True, exists=False),
    help='import saved settings from file PATH',
    cls=StorageManagementOption,
)
@click.version_option(version=dpp.__version__, prog_name=PROG_NAME)
@click.argument('service', required=False)
@click.pass_context
def derivepassphrase(
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
) -> None:
    """Derive a strong passphrase, deterministically, from a master secret.

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
                    raise AssertionError(  # noqa: TRY003
                        f'Unknown option group for {param!r}'  # noqa: EM102
                    )
                case _:
                    group = click.Option
            options_in_group.setdefault(group, []).append(param)
        params_by_str[param.human_readable_name] = param
        for name in param.opts + param.secondary_opts:
            params_by_str[name] = param

    def is_param_set(param: click.Parameter):
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

    def get_config() -> dpp_types.VaultConfig:
        try:
            return _load_config()
        except FileNotFoundError:
            return {'services': {}}
        except Exception as e:  # noqa: BLE001
            ctx.fail(f'cannot load config: {e}')

    configuration: dpp_types.VaultConfig

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
    sv_options = options_in_group[PasswordGenerationOption] + [
        params_by_str['--notes'],
        params_by_str['--delete'],
    ]
    sv_options.remove(params_by_str['--key'])
    sv_options.remove(params_by_str['--phrase'])
    for param in sv_options:
        if is_param_set(param) and not service:
            opt_str = param.opts[0]
            msg = f'{opt_str} requires a SERVICE'
            raise click.UsageError(msg)
    for param in [params_by_str['--key'], params_by_str['--phrase']]:
        if is_param_set(param) and not (
            service or is_param_set(params_by_str['--config'])
        ):
            opt_str = param.opts[0]
            msg = f'{opt_str} requires a SERVICE or --config'
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

    if edit_notes:
        assert service is not None
        configuration = get_config()
        text = DEFAULT_NOTES_TEMPLATE + configuration['services'].get(
            service, cast(dpp_types.VaultConfigServicesSettings, {})
        ).get('notes', '')
        notes_value = click.edit(text=text)
        if notes_value is not None:
            notes_lines = collections.deque(notes_value.splitlines(True))
            while notes_lines:
                line = notes_lines.popleft()
                if line.startswith(DEFAULT_NOTES_MARKER):
                    notes_value = ''.join(notes_lines)
                    break
            else:
                if not notes_value.strip():
                    ctx.fail('not saving new notes: user aborted request')
            configuration['services'].setdefault(service, {})['notes'] = (
                notes_value.strip('\n')
            )
            _save_config(configuration)
    elif delete_service_settings:
        assert service is not None
        configuration = get_config()
        if service in configuration['services']:
            del configuration['services'][service]
            _save_config(configuration)
    elif delete_globals:
        configuration = get_config()
        if 'global' in configuration:
            del configuration['global']
            _save_config(configuration)
    elif clear_all_settings:
        _save_config({'services': {}})
    elif import_settings:
        try:
            # TODO: keep track of auto-close; try os.dup if feasible
            infile = (
                cast(TextIO, import_settings)
                if hasattr(import_settings, 'close')
                else click.open_file(os.fspath(import_settings), 'rt')
            )
            with infile:
                maybe_config = json.load(infile)
        except json.JSONDecodeError as e:
            ctx.fail(f'Cannot load config: cannot decode JSON: {e}')
        except OSError as e:
            ctx.fail(f'Cannot load config: {e.strerror}')
        if dpp_types.is_vault_config(maybe_config):
            _save_config(maybe_config)
        else:
            ctx.fail('not a valid config')
    elif export_settings:
        configuration = get_config()
        try:
            # TODO: keep track of auto-close; try os.dup if feasible
            outfile = (
                cast(TextIO, export_settings)
                if hasattr(export_settings, 'close')
                else click.open_file(os.fspath(export_settings), 'wt')
            )
            with outfile:
                json.dump(configuration, outfile)
        except OSError as e:
            ctx.fail(f'cannot write config: {e.strerror}')
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
            {},
            cast(dict[str, Any], configuration.get('global', {})),
        )
        if use_key:
            try:
                key = base64.standard_b64encode(_select_ssh_key()).decode(
                    'ASCII'
                )
            except IndexError:
                ctx.fail('no valid SSH key selected')
            except (LookupError, RuntimeError) as e:
                ctx.fail(str(e))
        elif use_phrase:
            maybe_phrase = _prompt_for_passphrase()
            if not maybe_phrase:
                ctx.fail('no passphrase given')
            else:
                phrase = maybe_phrase
        if store_config_only:
            view: collections.ChainMap[str, Any]
            view = (
                collections.ChainMap(*settings.maps[:2])
                if service
                else settings.parents.parents
            )
            if use_key:
                view['key'] = key
                for m in view.maps:
                    m.pop('phrase', '')
            elif use_phrase:
                view['phrase'] = phrase
                for m in view.maps:
                    m.pop('key', '')
            if not view.maps[0]:
                settings_type = 'service' if service else 'global'
                msg = (
                    f'cannot update {settings_type} settings without '
                    f'actual settings'
                )
                raise click.UsageError(msg)
            if service:
                configuration['services'].setdefault(service, {}).update(view)  # type: ignore[typeddict-item]
            else:
                configuration.setdefault('global', {}).update(view)  # type: ignore[typeddict-item]
            assert dpp_types.is_vault_config(
                configuration
            ), f'invalid vault configuration: {configuration!r}'
            _save_config(configuration)
        else:
            if not service:
                msg = 'SERVICE is required'
                raise click.UsageError(msg)
            kwargs: dict[str, Any] = {
                k: v
                for k, v in settings.items()
                if k in service_keys and v is not None
            }

            # If either --key or --phrase are given, use that setting.
            # Otherwise, if both key and phrase are set in the config,
            # one must be global (ignore it) and one must be
            # service-specific (use that one). Otherwise, if only one of
            # key and phrase is set in the config, use that one.  In all
            # these above cases, set the phrase via
            # derivepassphrase.Vault.phrase_from_key if a key is
            # given. Finally, if nothing is set, error out.
            def key_to_phrase(
                key: str | bytes | bytearray,
            ) -> bytes | bytearray:
                return dpp.Vault.phrase_from_key(
                    base64.standard_b64decode(key)
                )

            if use_key or use_phrase:
                if use_key:
                    kwargs['phrase'] = key_to_phrase(key)
                else:
                    kwargs['phrase'] = phrase
                    kwargs.pop('key', '')
            elif kwargs.get('phrase') and kwargs.get('key'):
                if any('key' in m for m in settings.maps[:2]):
                    kwargs['phrase'] = key_to_phrase(kwargs.pop('key'))
                else:
                    kwargs.pop('key')
            elif kwargs.get('key'):
                kwargs['phrase'] = key_to_phrase(kwargs.pop('key'))
            elif kwargs.get('phrase'):
                pass
            else:
                msg = (
                    'no passphrase or key given on command-line '
                    'or in configuration'
                )
                raise click.UsageError(msg)
            vault = dpp.Vault(**kwargs)
            result = vault.generate(service)
            click.echo(result.decode('ASCII'))


if __name__ == '__main__':
    derivepassphrase()
