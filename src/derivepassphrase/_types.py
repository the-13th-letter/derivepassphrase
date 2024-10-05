# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Types used by derivepassphrase."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from typing_extensions import (
    NamedTuple,
    NotRequired,
    TypedDict,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import Literal

    from typing_extensions import (
        Any,
        Required,
        TypeIs,
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
    """"""
    phrase: NotRequired[str]
    """"""
    unicode_normalization_form: NotRequired[
        Literal['NFC', 'NFD', 'NFKC', 'NFKD']
    ]
    """"""


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
    """"""
    length: NotRequired[int]
    """"""
    repeat: NotRequired[int]
    """"""
    lower: NotRequired[int]
    """"""
    upper: NotRequired[int]
    """"""
    number: NotRequired[int]
    """"""
    space: NotRequired[int]
    """"""
    dash: NotRequired[int]
    """"""
    symbol: NotRequired[int]
    """"""


_VaultConfig = TypedDict(
    '_VaultConfig',
    {'global': NotRequired[VaultConfigGlobalSettings]},
    total=False,
)


class VaultConfig(TypedDict, _VaultConfig, total=False):
    r"""Configuration for vault.  For typing purposes.

    Usually stored as JSON.

    Attributes:
        global (NotRequired[VaultConfigGlobalSettings]):
            Global settings.
        services (Required[dict[str, VaultConfigServicesSettings]]):
            Service-specific settings.

    """

    services: Required[dict[str, VaultConfigServicesSettings]]


def validate_vault_config(  # noqa: C901,PLR0912,PLR0915
    obj: Any,  # noqa: ANN401
    /,
    *,
    allow_unknown_settings: bool = False,
    allow_derivepassphrase_extensions: bool = False,
) -> None:
    """Check that `obj` is a valid vault config.

    Args:
        obj:
            The object to test.
        allow_unknown_settings:
            If false, abort on unknown settings.
        allow_derivepassphrase_extensions:
            If true, allow `derivepassphrase` extensions.

    Raises:
        TypeError:
            An entry in the vault config, or the vault config itself,
            has the wrong type.
        ValueError:
            An entry in the vault config is not allowed, or has a
            disallowed value.

    """

    def as_json_path_string(json_path: Sequence[str], /) -> str:
        return ''.join('.' + repr(x) for x in json_path)

    err_obj_not_a_dict = 'vault config is not a dict'
    err_non_str_service_name = (
        'vault config contains non-string service name {!r}'
    )

    def err_not_a_dict(json_path: Sequence[str], /) -> str:
        json_path_str = as_json_path_string(json_path)
        return f'vault config entry {json_path_str} is not a dict'

    def err_not_a_string(json_path: Sequence[str], /) -> str:
        json_path_str = as_json_path_string(json_path)
        return f'vault config entry {json_path_str} is not a string'

    def err_not_an_int(json_path: Sequence[str], /) -> str:
        json_path_str = as_json_path_string(json_path)
        return f'vault config entry {json_path_str} is not an integer'

    def err_derivepassphrase_extension(
        key: str, json_path: Sequence[str], /
    ) -> str:
        json_path_str = as_json_path_string(json_path)
        return (
            f'vault config entry {json_path_str} uses '
            f'`derivepassphrase` extension {key!r}'
        )

    def err_unknown_setting(key: str, json_path: Sequence[str], /) -> str:
        json_path_str = as_json_path_string(json_path)
        return (
            f'vault config entry {json_path_str} uses '
            f'unknown setting {key!r}'
        )

    def err_bad_number(
        key: str,
        json_path: Sequence[str],
        /,
        *,
        strictly_positive: bool = False,
    ) -> str:
        json_path_str = as_json_path_string((*json_path, key))
        return f'vault config entry {json_path_str} is ' + (
            'not positive' if strictly_positive else 'negative'
        )

    if not isinstance(obj, dict):
        raise TypeError(err_obj_not_a_dict)
    if 'global' in obj:
        o_global = obj['global']
        if not isinstance(o_global, dict):
            raise TypeError(err_not_a_dict(['global']))
        for key, value in o_global.items():
            # Use match/case here once Python 3.9 becomes unsupported.
            if key in {'key', 'phrase'}:
                if not isinstance(value, str):
                    raise TypeError(err_not_a_dict(['global', key]))
            elif key == 'unicode_normalization_form':
                if not isinstance(value, str):
                    raise TypeError(err_not_a_dict(['global', key]))
                if not allow_derivepassphrase_extensions:
                    raise ValueError(
                        err_derivepassphrase_extension(key, ('global',))
                    )
            elif not allow_unknown_settings:
                raise ValueError(err_unknown_setting(key, ('global',)))
    if not isinstance(obj.get('services'), dict):
        raise TypeError(err_not_a_dict(['services']))
    for sv_name, service in obj['services'].items():
        if not isinstance(sv_name, str):
            raise TypeError(err_non_str_service_name.format(sv_name))
        if not isinstance(service, dict):
            raise TypeError(err_not_a_dict(['services', sv_name]))
        for key, value in service.items():
            # Use match/case here once Python 3.9 becomes unsupported.
            if key in {'notes', 'phrase', 'key'}:
                if not isinstance(value, str):
                    raise TypeError(
                        err_not_a_string(['services', sv_name, key])
                    )
            elif key == 'length':
                if not isinstance(value, int):
                    raise TypeError(err_not_an_int(['services', sv_name, key]))
                if value < 1:
                    raise ValueError(
                        err_bad_number(
                            key,
                            ['services', sv_name],
                            strictly_positive=True,
                        )
                    )
            elif key in {
                'repeat',
                'lower',
                'upper',
                'number',
                'space',
                'dash',
                'symbol',
            }:
                if not isinstance(value, int):
                    raise TypeError(err_not_an_int(['services', sv_name, key]))
                if value < 0:
                    raise ValueError(
                        err_bad_number(
                            key,
                            ['services', sv_name],
                            strictly_positive=False,
                        )
                    )
            elif not allow_unknown_settings:
                raise ValueError(
                    err_unknown_setting(key, ['services', sv_name])
                )


def is_vault_config(obj: Any) -> TypeIs[VaultConfig]:  # noqa: ANN401
    """Check if `obj` is a valid vault config, according to typing.

    Args:
        obj: The object to test.

    Returns:
        True if this is a vault config, false otherwise.

    """
    try:
        validate_vault_config(
            obj,
            allow_unknown_settings=True,
            allow_derivepassphrase_extensions=True,
        )
    except (TypeError, ValueError) as exc:
        if 'vault config ' not in str(exc):  # pragma: no cover
            raise  # noqa: DOC501
        return False
    return True


class KeyCommentPair(NamedTuple):
    """SSH key plus comment pair.  For typing purposes.

    Attributes:
        key: SSH key.
        comment: SSH key comment.

    """

    key: bytes | bytearray
    """"""
    comment: bytes | bytearray
    """"""


class SSH_AGENTC(enum.Enum):  # noqa: N801
    """SSH agent protocol numbers: client requests.

    Attributes:
        REQUEST_IDENTITIES:
            List identities.  Expecting
            [`SSH_AGENT.IDENTITIES_ANSWER`][].
        SIGN_REQUEST:
            Sign data.  Expecting [`SSH_AGENT.SIGN_RESPONSE`][].
        ADD_IDENTITY:
            Add an (SSH2) identity.
        REMOVE_IDENTITY:
            Remove an (SSH2) identity.
        ADD_ID_CONSTRAINED:
            Add an (SSH2) identity, including key constraints.

    """

    REQUEST_IDENTITIES: int = 11
    """"""
    SIGN_REQUEST: int = 13
    """"""
    ADD_IDENTITY: int = 17
    """"""
    REMOVE_IDENTITY: int = 18
    """"""
    ADD_ID_CONSTRAINED: int = 25
    """"""


class SSH_AGENT(enum.Enum):  # noqa: N801
    """SSH agent protocol numbers: server replies.

    Attributes:
        FAILURE:
            Generic failure code.
        SUCCESS:
            Generic success code.
        IDENTITIES_ANSWER:
            Successful answer to [`SSH_AGENTC.REQUEST_IDENTITIES`][].
        SIGN_RESPONSE:
            Successful answer to [`SSH_AGENTC.SIGN_REQUEST`][].

    """

    FAILURE: int = 5
    """"""
    SUCCESS: int = 6
    """"""
    IDENTITIES_ANSWER: int = 12
    """"""
    SIGN_RESPONSE: int = 14
    """"""
