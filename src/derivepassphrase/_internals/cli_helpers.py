# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

# ruff: noqa: TRY400

"""Helper functions for the derivepassphrase command-line.

Warning:
    Non-public module (implementation detail), provided for didactical and
    educational purposes only. Subject to change without notice, including
    removal.

"""

from __future__ import annotations

import base64
import copy
import enum
import json
import logging
import os
import pathlib
import shlex
import sys
import unicodedata
from typing import TYPE_CHECKING, Callable, NoReturn, TextIO, cast

import click
import click.shell_completion
from typing_extensions import Any

import derivepassphrase as dpp
from derivepassphrase import _types, ssh_agent, vault
from derivepassphrase._internals import cli_messages as _msg

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

if TYPE_CHECKING:
    import socket
    from collections.abc import (
        Iterator,
        Sequence,
    )

    from typing_extensions import Buffer

__author__ = dpp.__author__
__version__ = dpp.__version__

PROG_NAME = _msg.PROG_NAME
KEY_DISPLAY_LENGTH = 50

# Error messages
INVALID_VAULT_CONFIG = 'Invalid vault config'
AGENT_COMMUNICATION_ERROR = 'Error communicating with the SSH agent'
NO_SUITABLE_KEYS = 'No suitable SSH keys were found'
EMPTY_SELECTION = 'Empty selection'


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


def shell_complete_path(
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


def is_completable_item(obj: object) -> bool:
    """Return whether the item is completable on the command-line.

    The item is completable if and only if it contains no ASCII control
    characters (U+0000 through U+001F, and U+007F).

    """
    obj = str(obj)
    forbidden = frozenset(chr(i) for i in range(32)) | {'\x7f'}
    return not any(f in obj for f in forbidden)


def shell_complete_service(
    ctx: click.Context,
    parameter: click.Parameter,
    value: str,
) -> list[str | click.shell_completion.CompletionItem]:
    """Return known vault service names as completion items.

    Service names are looked up in the vault configuration file.  All
    errors will be suppressed.  Additionally, any service names deemed
    not completable as per [`is_completable_item`][] will be silently
    skipped.

    """
    del ctx, parameter
    try:
        config = load_config()
        return sorted(
            sv
            for sv in config['services']
            if sv.startswith(value) and is_completable_item(sv)
        )
    except FileNotFoundError:
        try:
            config, _exc = migrate_and_load_old_config()
            return sorted(
                sv
                for sv in config['services']
                if sv.startswith(value) and is_completable_item(sv)
            )
        except FileNotFoundError:
            return []
    except Exception:  # noqa: BLE001
        return []


# Vault
# =====

config_filename_table = {
    None: '.',
    'vault': 'vault.json',
    'user configuration': 'config.toml',
    # TODO(the-13th-letter): Remove the old settings.json file.
    # https://the13thletter.info/derivepassphrase/latest/upgrade-notes.html#v1.0-old-settings-file
    'old settings.json': 'settings.json',
    'notes backup': 'old-notes.txt',
}


def config_filename(
    subsystem: str | None = 'old settings.json',
) -> pathlib.Path:
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
    path = pathlib.Path(
        os.getenv(PROG_NAME.upper() + '_PATH')
        or click.get_app_dir(PROG_NAME, force_posix=True)
    )
    try:
        filename = config_filename_table[subsystem]
    except (KeyError, TypeError):  # pragma: no cover
        msg = f'Unknown configuration subsystem: {subsystem!r}'
        raise AssertionError(msg) from None
    return path / filename


def load_config() -> _types.VaultConfig:
    """Load a vault(1)-compatible config from the application directory.

    The filename is obtained via [`config_filename`][].  This must be
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
    filename = config_filename(subsystem='vault')
    with filename.open('rb') as fileobj:
        data = json.load(fileobj)
    if not _types.is_vault_config(data):
        raise ValueError(INVALID_VAULT_CONFIG)
    return data


# TODO(the-13th-letter): Remove this function.
# https://the13thletter.info/derivepassphrase/latest/upgrade-notes.html#v1.0-old-settings-file
def migrate_and_load_old_config() -> tuple[_types.VaultConfig, OSError | None]:
    """Load and migrate a vault(1)-compatible config.

    The (old) filename is obtained via [`config_filename`][].  This
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
    new_filename = config_filename(subsystem='vault')
    old_filename = config_filename(subsystem='old settings.json')
    with old_filename.open('rb') as fileobj:
        data = json.load(fileobj)
    if not _types.is_vault_config(data):
        raise ValueError(INVALID_VAULT_CONFIG)
    try:
        old_filename.rename(new_filename)
    except OSError as exc:
        return data, exc
    else:
        return data, None


def save_config(config: _types.VaultConfig, /) -> None:
    """Save a vault(1)-compatible config to the application directory.

    The filename is obtained via [`config_filename`][].  The config
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
        raise ValueError(INVALID_VAULT_CONFIG)
    filename = config_filename(subsystem='vault')
    filedir = filename.resolve().parent
    filedir.mkdir(parents=True, exist_ok=True)
    with filename.open('w', encoding='UTF-8') as fileobj:
        json.dump(
            config, fileobj, ensure_ascii=False, indent=2, sort_keys=True
        )


def load_user_config() -> dict[str, Any]:
    """Load the user config from the application directory.

    The filename is obtained via [`config_filename`][].

    Returns:
        The user configuration, as a nested `dict`.

    Raises:
        OSError:
            There was an OS error accessing the file.
        ValueError:
            The data loaded from the file is not a valid configuration
            file.

    """
    filename = config_filename(subsystem='user configuration')
    with filename.open('rb') as fileobj:
        return tomllib.load(fileobj)


def get_suitable_ssh_keys(
    conn: ssh_agent.SSHAgentClient | socket.socket | None = None, /
) -> Iterator[_types.SSHKeyCommentPair]:
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
            raise RuntimeError(AGENT_COMMUNICATION_ERROR) from exc
        suitable_keys = copy.copy(all_key_comment_pairs)
        for pair in all_key_comment_pairs:
            key, _comment = pair
            if vault.Vault.is_suitable_ssh_key(key, client=client):
                yield pair
    if not suitable_keys:  # pragma: no cover
        raise LookupError(NO_SUITABLE_KEYS)


def prompt_for_selection(
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
            raise IndexError(EMPTY_SELECTION)
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
        raise IndexError(EMPTY_SELECTION) from None
    return 0


def select_ssh_key(
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
    suitable_keys = list(get_suitable_ssh_keys(conn))
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
    choice = prompt_for_selection(
        key_listing,
        heading='Suitable SSH keys:',
        single_choice_prompt='Use this key?',
        ctx=ctx,
    )
    return suitable_keys[choice].key


def prompt_for_passphrase() -> str:
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


def toml_key(*parts: str) -> str:
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


class ORIGIN(enum.Enum):
    """The origin of a setting, if not from the user configuration file.

    Attributes:
        INTERACTIVE (str): interactive input

    """

    INTERACTIVE = 'interactive input'
    """"""


def check_for_misleading_passphrase(
    key: tuple[str, ...] | ORIGIN,
    value: dict[str, Any],
    *,
    main_config: dict[str, Any],
    ctx: click.Context | None = None,
) -> None:
    """Check for a misleading passphrase according to user configuration.

    Look up the desired Unicode normalization form in the user
    configuration, and if the passphrase is not normalized according to
    this form, issue a warning to the user.

    Args:
        key:
            A vault configuration key or an origin of the
            value/configuration section, e.g. [`ORIGIN.INTERACTIVE`][],
            or `("global",)`, or `("services", "foo")`.
        value:
            The vault configuration section maybe containing
            a passphrase to vet.
        main_config:
            The parsed main user configuration.
        ctx:
            The click context.  This is necessary to pass output options
            set on the context to the logging machinery.

    Raises:
        AssertionError:
            The main user configuration is invalid.

    """
    form_key = 'unicode-normalization-form'
    default_form: str = main_config.get('vault', {}).get(
        f'default-{form_key}', 'NFC'
    )
    form_dict: dict[str, dict] = main_config.get('vault', {}).get(form_key, {})
    form: Any = (
        default_form
        if isinstance(key, ORIGIN) or key == ('global',)
        else form_dict.get(key[1], default_form)
    )
    config_key = (
        toml_key('vault', key[1], form_key)
        if isinstance(key, tuple) and len(key) > 1 and key[1] in form_dict
        else f'vault.default-{form_key}'
    )
    if form not in {'NFC', 'NFD', 'NFKC', 'NFKD'}:
        msg = f'Invalid value {form!r} for config key {config_key}'
        raise AssertionError(msg)
    logger = logging.getLogger(PROG_NAME)
    formatted_key = (
        key.value if isinstance(key, ORIGIN) else _types.json_path(key)
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


def default_error_callback(
    message: Any,  # noqa: ANN401
    /,
    *_args: Any,  # noqa: ANN401
    **_kwargs: Any,  # noqa: ANN401
) -> NoReturn:  # pragma: no cover
    """Calls [`sys.exit`][] on its first argument, ignoring the rest."""
    sys.exit(message)


def key_to_phrase(
    key: str | Buffer,
    /,
    *,
    error_callback: Callable[..., NoReturn] = default_error_callback,
) -> bytes:
    """Return the equivalent master passphrase, or abort.

    This wrapper around [`vault.Vault.phrase_from_key`][] emits
    user-facing error messages if no equivalent master passphrase can be
    obtained from the key, because this is the first point of contact
    with the SSH agent.

    """
    key = base64.standard_b64decode(key)
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


def print_config_as_sh_script(
    config: _types.VaultConfig,
    /,
    *,
    outfile: TextIO,
    prog_name_list: Sequence[str],
) -> None:
    """Print the given vault configuration as a sh(1) script.

    This implements the `--export-as=sh` option of `derivepassphrase vault`.

    Args:
        config:
            The configuration to serialize.
        outfile:
            A file object to write the output to.
        prog_name_list:
            A list of (subcommand) names for the command emitting this
            output, e.g. `["derivepassphrase", "vault"]`.

    """
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
