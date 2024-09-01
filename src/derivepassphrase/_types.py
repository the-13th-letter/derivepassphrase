# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Types used by derivepassphrase."""

from __future__ import annotations

import enum
from typing import Literal, NamedTuple, TypeGuard

from typing_extensions import (
    Any,
    NotRequired,
    Required,
    TypedDict,
)

__all__ = (
    'SSH_AGENT',
    'SSH_AGENTC',
    'KeyCommentPair',
    'VaultConfig',
    'is_vault_config',
)


class VaultConfigGlobalSettings(TypedDict, total=False):
    r"""Configuration for vault: global settings.

    Attributes:
        key:
            The base64-encoded ssh public key to use, overriding the
            master passphrase. Optional.
        phrase:
            The master passphrase. Optional.
        unicode_normalization_form:
            The preferred Unicode normalization form; we warn the user
            if textual passphrases do not match their normalized forms.
            Optional, and a `derivepassphrase` extension.

    """

    key: NotRequired[str]
    phrase: NotRequired[str]
    unicode_normalization_form: NotRequired[
        Literal['NFC', 'NFD', 'NFKC', 'NFKD']
    ]


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
        for key in ('key', 'phrase', 'unicode_normalization_form'):
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


class KeyCommentPair(NamedTuple):
    """SSH key plus comment pair.  For typing purposes.

    Attributes:
        key: SSH key.
        comment: SSH key comment.

    """

    key: bytes | bytearray
    comment: bytes | bytearray


class SSH_AGENTC(enum.Enum):  # noqa: N801
    """SSH agent protocol numbers: client requests.

    Attributes:
        REQUEST_IDENTITIES:
            List identities.  Expecting `SSH_AGENT.IDENTITIES_ANSWER`.
        SIGN_REQUEST:
            Sign data.  Expecting `SSH_AGENT.SIGN_RESPONSE`.

    """

    REQUEST_IDENTITIES: int = 11
    SIGN_REQUEST: int = 13


class SSH_AGENT(enum.Enum):  # noqa: N801
    """SSH agent protocol numbers: server replies.

    Attributes:
        FAILURE:
            Generic failure code.
        SUCCESS:
            Generic success code.
        IDENTITIES_ANSWER:
            Successful answer to `SSH_AGENTC.REQUEST_IDENTITIES`.
        SIGN_RESPONSE:
            Successful answer to `SSH_AGENTC.SIGN_REQUEST`.

    """

    FAILURE: int = 5
    SUCCESS: int = 6
    IDENTITIES_ANSWER: int = 12
    SIGN_RESPONSE: int = 14
