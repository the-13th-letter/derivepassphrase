# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Foreign configuration exporter for derivepassphrase."""

from __future__ import annotations

import os

import derivepassphrase as dpp

__author__ = dpp.__author__
__version__ = dpp.__version__

__all__ = ()


def get_vault_key() -> bytes:
    """Automatically determine the vault(1) master key/password.

    Query the `VAULT_KEY`, `LOGNAME`, `USER` and `USERNAME` environment
    variables, in that order.  This is the same algorithm that vault
    uses.

    Returns:
        The master key/password.  This is generally used as input to
        a key-derivation function to determine the *actual* encryption
        and signing keys for the vault configuration.

    Raises:
        KeyError:
            We cannot find any of the named environment variables.
            Please set `VAULT_KEY` manually to the desired value.

    """
    username = (
        os.environb.get(b'VAULT_KEY')
        or os.environb.get(b'LOGNAME')
        or os.environb.get(b'USER')
        or os.environb.get(b'USERNAME')
    )
    if not username:
        env_var = 'VAULT_KEY'
        raise KeyError(env_var)
    return username


def get_vault_path() -> str | bytes | os.PathLike:
    """Automatically determine the vault(1) configuration path.

    Query the `VAULT_PATH` environment variable, or default to
    `~/.vault`.  This is the same algorithm that vault uses.  If not
    absolute, then `VAULT_PATH` is relative to the home directory.

    Returns:
        The vault configuration path.  Depending on the vault version,
        this may be a file or a directory.

    Raises:
        RuntimeError:
            We cannot determine the home directory.  Please set `HOME`
            manually to the correct value.

    """
    result = os.path.join(
        os.path.expanduser('~'), os.environ.get('VAULT_PATH', '.vault')
    )
    if result.startswith('~'):
        msg = 'Cannot determine home directory'
        raise RuntimeError(msg)
    return result
