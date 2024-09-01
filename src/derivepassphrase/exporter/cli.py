# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Command-line interface for derivepassphrase_export."""

from __future__ import annotations

import base64
import importlib
import json
import logging
from typing import TYPE_CHECKING, Any, Literal

import click
from typing_extensions import assert_never

import derivepassphrase as dpp
from derivepassphrase import _types, exporter

if TYPE_CHECKING:
    import os
    import types
    from collections.abc import Sequence

__author__ = dpp.__author__
__version__ = dpp.__version__

__all__ = ('derivepassphrase_export',)

PROG_NAME = 'derivepassphrase_export'


def _load_data(
    fmt: Literal['v0.2', 'v0.3', 'storeroom'],
    path: str | bytes | os.PathLike[str],
    key: bytes,
) -> Any:  # noqa: ANN401
    contents: bytes
    module: types.ModuleType
    match fmt:
        case 'v0.2':
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
        case 'v0.3':
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
        case 'storeroom':
            module = importlib.import_module(
                'derivepassphrase.exporter.storeroom'
            )
            if module.STUBBED:
                raise ModuleNotFoundError
            return module.export_storeroom_data(path, key)
        case _:  # pragma: no cover
            assert_never(fmt)


@click.command(
    context_settings={'help_option_names': ['-h', '--help']},
)
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
def derivepassphrase_export(
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
    Depending on the configuration format, this may either be a file or
    a directory.  Supports the vault "v0.2", "v0.3" and "storeroom"
    formats.

    If PATH is explicitly given as `VAULT_PATH`, then use the
    `VAULT_PATH` environment variable to determine the correct path.
    (Use `./VAULT_PATH` or similar to indicate a file/directory actually
    named `VAULT_PATH`.)

    """
    logging.basicConfig()
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
            logging.info('Cannot load as %s: %s', fmt, path)
            continue
        except OSError as exc:
            click.echo(
                (
                    f'{PROG_NAME}: ERROR: Cannot parse {path!r} as '
                    f'a valid config: {exc.strerror}: {exc.filename!r}'
                ),
                err=True,
            )
            ctx.exit(1)
        except ModuleNotFoundError:
            # TODO(the-13th-letter): Use backslash continuation.
            # https://github.com/nedbat/coveragepy/issues/1836
            msg = f"""
{PROG_NAME}: ERROR: Cannot load the required Python module "cryptography".
{PROG_NAME}: INFO: pip users: see the "export" extra.
""".lstrip('\n')
            click.echo(msg, nl=False, err=True)
            ctx.exit(1)
        else:
            if not _types.is_vault_config(config):
                click.echo(
                    f'{PROG_NAME}: ERROR: Invalid vault config: {config!r}',
                    err=True,
                )
                ctx.exit(1)
            click.echo(json.dumps(config, indent=2, sort_keys=True))
            break
    else:
        click.echo(
            f'{PROG_NAME}: ERROR: Cannot parse {path!r} as a valid config.',
            err=True,
        )
        ctx.exit(1)


if __name__ == '__main__':
    derivepassphrase_export()
