# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Common typing declarations for the parent module."""

from __future__ import annotations

from typing import TypeGuard

from typing_extensions import (
    Any,
    NotRequired,
    Required,
    TypedDict,
)

import derivepassphrase

__author__ = derivepassphrase.__author__
__version__ = derivepassphrase.__version__


class VaultConfigGlobalSettings(TypedDict, total=False):
    r"""Configuration for vault: global settings.

    Attributes:
        key:
            The base64-encoded ssh public key to use, overriding the
            master passphrase. Optional.
        phrase:
            The master passphrase. Optional.

    """

    key: NotRequired[str]
    phrase: NotRequired[str]


class VaultConfigServicesSettings(VaultConfigGlobalSettings, total=False):
    r"""Configuration for vault: services settings.

    Attributes:
        notes:
            Optional notes for this service, to display to the user when
            generating the passphrase.
        length:
            Desired passphrase length.
        repeat:
            The maximum number of immediate character repetitions
            allowed in the passphrase.  Disabled if set to 0.
        lower:
            Optional constraint on ASCII lowercase characters.  If
            positive, include this many lowercase characters
            somewhere in the passphrase.  If 0, avoid lowercase
            characters altogether.
        upper:
            Same as `lower`, but for ASCII uppercase characters.
        number:
            Same as `lower`, but for ASCII digits.
        space:
            Same as `lower`, but for the space character.
        dash:
            Same as `lower`, but for the hyphen-minus and underscore
            characters.
        symbol:
            Same as `lower`, but for all other hitherto unlisted
            ASCII printable characters (except backquote).

    """

    notes: NotRequired[str]
    length: NotRequired[int]
    repeat: NotRequired[int]
    lower: NotRequired[int]
    upper: NotRequired[int]
    number: NotRequired[int]
    space: NotRequired[int]
    dash: NotRequired[int]
    symbol: NotRequired[int]


_VaultConfig = TypedDict(
    '_VaultConfig',
    {'global': NotRequired[VaultConfigGlobalSettings]},
    total=False,
)


class VaultConfig(TypedDict, _VaultConfig, total=False):
    r"""Configuration for vault.

    Usually stored as JSON.

    Attributes:
        global (NotRequired[VaultConfigGlobalSettings]):
            Global settings.
        services (Required[dict[str, VaultConfigServicesSettings]]):
            Service-specific settings.

    """

    services: Required[dict[str, VaultConfigServicesSettings]]


def is_vault_config(obj: Any) -> TypeGuard[VaultConfig]:
    """Check if `obj` is a valid vault config, according to typing.

    Args:
        obj: The object to test.

    Returns:
        True if this is a vault config, false otherwise.

    """
    if not isinstance(obj, dict):
        return False
    if 'global' in obj:
        o_global = obj['global']
        if not isinstance(o_global, dict):
            return False
        for key in ('key', 'phrase'):
            if key in o_global and not isinstance(o_global[key], str):
                return False
        if 'key' in o_global and 'phrase' in o_global:
            return False
    if not isinstance(obj.get('services'), dict):
        return False
    for sv_name, service in obj['services'].items():
        if not isinstance(sv_name, str):
            return False
        if not isinstance(service, dict):
            return False
        for key, value in service.items():
            match key:
                case 'notes' | 'phrase' | 'key':
                    if not isinstance(value, str):
                        return False
                case 'length':
                    if not isinstance(value, int) or value < 1:
                        return False
                case _:
                    if not isinstance(value, int) or value < 0:
                        return False
        if 'key' in service and 'phrase' in service:
            return False
    return True
