# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Types used by derivepassphrase."""

from __future__ import annotations

import enum
import math
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

    def maybe_quote(x: str) -> str:
        chars = (
            frozenset('abcdefghijklmnopqrstuvwxyz')
            | frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
            | frozenset('0123456789')
            | frozenset('_')
        )
        initial = (
            frozenset('abcdefghijklmnopqrstuvwxyz')
            | frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
            | frozenset('_')
        )
        return (
            x if x and set(x).issubset(chars) and x[:1] in initial else repr(x)
        )

    def as_json_path_string(json_path: Sequence[str], /) -> str:
        return ''.join('.' + maybe_quote(x) for x in json_path)

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
    queue_to_check: list[tuple[dict[str, Any], tuple[str, ...]]] = []
    if 'global' in obj:
        o_global = obj['global']
        if not isinstance(o_global, dict):
            raise TypeError(err_not_a_dict(['global']))
        queue_to_check.append((o_global, ('global',)))
    if not isinstance(obj.get('services'), dict):
        raise TypeError(err_not_a_dict(['services']))
    for sv_name, service in obj['services'].items():
        if not isinstance(sv_name, str):
            raise TypeError(err_non_str_service_name.format(sv_name))
        if not isinstance(service, dict):
            raise TypeError(err_not_a_dict(['services', sv_name]))
        queue_to_check.append((service, ('services', sv_name)))
    for settings, path in queue_to_check:
        for key, value in settings.items():
            # Use match/case here once Python 3.9 becomes unsupported.
            if key in {'key', 'phrase'}:
                if not isinstance(value, str):
                    raise TypeError(err_not_a_string((*path, key)))
            elif key == 'unicode_normalization_form' and path == ('global',):
                if not isinstance(value, str):
                    raise TypeError(err_not_a_string((*path, key)))
                if not allow_derivepassphrase_extensions:
                    raise ValueError(err_derivepassphrase_extension(key, path))
            elif key == 'notes' and path != ('global',):
                if not isinstance(value, str):
                    raise TypeError(err_not_a_string((*path, key)))
            elif key == 'length':
                if not isinstance(value, int):
                    raise TypeError(err_not_an_int((*path, key)))
                if value < 1:
                    raise ValueError(
                        err_bad_number(key, path, strictly_positive=True)
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
                    raise TypeError(err_not_an_int((*path, key)))
                if value < 0:
                    raise ValueError(
                        err_bad_number(key, path, strictly_positive=False)
                    )
            elif not allow_unknown_settings:
                raise ValueError(err_unknown_setting(key, path))


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


def js_truthiness(value: Any, /) -> bool:  # noqa: ANN401
    """Return the truthiness of the value, according to JavaScript/ECMAScript.

    Like Python, ECMAScript considers certain values to be false in
    a boolean context, and every other value to be true.  These
    considerations do not agree: ECMAScript considers [`math.nan`][] to
    be false too, and empty arrays and objects/dicts to be true,
    contrary to Python.  Because of these discrepancies, we cannot defer
    to [`bool`][] for ECMAScript truthiness checking, and need
    a separate, explicit predicate.

    (Some falsy values in ECMAScript aren't defined in Python:
    `undefined`, and `document.all`.  We do not implement support for
    those.)

    !!! note

        We cannot use a simple `value not in falsy_values` check,
        because [`math.nan`][] behaves in annoying and obstructive ways.
        In general, `float('NaN') == float('NaN')` is false, and
        `float('NaN') != math.nan` and `math.nan != math.nan` are true.
        CPython says `float('NaN') in [math.nan]` is false, PyPy3 says
        it is true.  Seemingly the only reliable and portable way to
        check for [`math.nan`][] is to use [`math.isnan`][] directly.

    Args:
        value: The value to test.

    """  # noqa: RUF002
    try:
        if value in {None, False, 0, 0.0, ''}:
            return False
    except TypeError:
        # All falsy values are hashable, so this can't be falsy.
        return True
    return not (isinstance(value, float) and math.isnan(value))


def clean_up_falsy_vault_config_values(obj: Any) -> None:  # noqa: ANN401,C901,PLR0912
    """Convert falsy values in a vault config to correct types, in-place.

    Needed for compatibility with vault(1), which sometimes uses only
    truthiness checks.

    If vault(1) considered `obj` to be valid, then after clean up,
    `obj` will be valid as per [`validate_vault_config`][].

    Args:
        obj:
            A presumed valid vault configuration save for using falsy
            values of the wrong type.

    """
    if (  # pragma: no cover
        not isinstance(obj, dict)
        or 'services' not in obj
        or not isinstance(obj['services'], dict)
    ):
        # config is invalid
        return
    service_objects = list(obj['services'].values())
    if not all(  # pragma: no cover
        isinstance(service_obj, dict) for service_obj in service_objects
    ):
        # config is invalid
        return
    if 'global' in obj:
        if isinstance(obj['global'], dict):
            service_objects.append(obj['global'])
        else:  # pragma: no cover
            # config is invalid
            return
    for service_obj in service_objects:
        for key, value in list(service_obj.items()):
            # Use match/case here once Python 3.9 becomes unsupported.
            if key == 'phrase':
                if not js_truthiness(value):
                    service_obj[key] = ''
            elif key in {'notes', 'key', 'length', 'repeat'}:
                if not js_truthiness(value):
                    service_obj.pop(key)
            elif key in {  # noqa: SIM102
                'lower',
                'upper',
                'number',
                'space',
                'dash',
                'symbol',
            }:
                if not js_truthiness(value) and value != 0:
                    service_obj.pop(key)


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
