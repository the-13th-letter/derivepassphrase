# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Types used by derivepassphrase."""

from __future__ import annotations

import enum
import json
import math
import string
import warnings
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from typing_extensions import (
    Buffer,
    NamedTuple,
    NotRequired,
    TypedDict,
    deprecated,
    get_overloads,
    overload,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from typing import Literal

    from typing_extensions import (
        Any,
        Required,
        TypeIs,
    )

__all__ = (
    'SSH_AGENT',
    'SSH_AGENTC',
    'SSHKeyCommentPair',
    'VaultConfig',
    'is_vault_config',
)


class _Omitted:
    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return '...'


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

    key: NotRequired[str]
    """"""
    phrase: NotRequired[str]
    """"""
    unicode_normalization_form: NotRequired[
        Literal['NFC', 'NFD', 'NFKC', 'NFKD']
    ]
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


class VaultConfigServicesSettings(VaultConfigGlobalSettings, total=False):
    r"""Configuration for vault: services settings.

    Attributes:
        notes:
            Optional notes for this service, to display to the user when
            generating the passphrase.
        key:
            As per the global settings.
        phrase:
            As per the global settings.
        unicode_normalization_form:
            As per the global settings.
        length:
            As per the global settings.
        repeat:
            As per the global settings.
        lower:
            As per the global settings.
        upper:
            As per the global settings.
        number:
            As per the global settings.
        space:
            As per the global settings.
        dash:
            As per the global settings.
        symbol:
            As per the global settings.

    """

    notes: NotRequired[str]
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


def json_path(path: Sequence[str | int], /) -> str:
    r"""Transform a series of keys and indices into a JSONPath selector.

    The resulting JSONPath selector conforms to RFC 9535, is always
    rooted at the JSON root node (i.e., starts with `$`), and only
    contains name and index selectors (in shorthand dot notation, where
    possible).

    Args:
        path:
            A sequence of object keys or array indices to navigate to
            the desired JSON value, starting from the root node.

    Returns:
        A valid JSONPath selector (a string) identifying the desired
        JSON value.

    Examples:
        >>> json_path(['global', 'phrase'])
        '$.global.phrase'
        >>> json_path(['services', 'service name with spaces', 'length'])
        '$.services["service name with spaces"].length'
        >>> json_path(['services', 'special\u000acharacters', 'notes'])
        '$.services["special\\ncharacters"].notes'
        >>> print(json_path(['services', 'special\u000acharacters', 'notes']))
        $.services["special\ncharacters"].notes
        >>> json_path(['custom_array', 2, 0])
        '$.custom_array[2][0]'

    """

    def needs_longhand(x: str | int) -> bool:
        initial = (
            frozenset(string.ascii_lowercase)
            | frozenset(string.ascii_uppercase)
            | frozenset('_')
        )
        chars = initial | frozenset(string.digits)
        return not (
            isinstance(x, str)
            and x
            and set(x).issubset(chars)
            and x[:1] in initial
        )

    chunks = ['$']
    chunks.extend(
        f'[{json.dumps(x)}]' if needs_longhand(x) else f'.{x}' for x in path
    )
    return ''.join(chunks)


class _VaultConfigValidator:
    INVALID_CONFIG_ERROR = 'vault config is invalid'

    def __init__(self, maybe_config: Any) -> None:  # noqa: ANN401
        self.maybe_config = maybe_config

    def traverse_path(self, path: tuple[str, ...]) -> Any:  # noqa: ANN401
        obj = self.maybe_config
        for key in path:
            obj = obj[key]
        return obj

    def walk_subconfigs(
        self,
    ) -> Iterator[tuple[tuple[str] | tuple[str, str], str, Any]]:
        obj = cast('dict[str, dict[str, Any]]', self.maybe_config)
        if isinstance(obj.get('global', False), dict):
            for k, v in list(obj['global'].items()):
                yield ('global',), k, v
        for sv_name, sv_obj in list(obj['services'].items()):
            for k, v in list(sv_obj.items()):
                yield ('services', sv_name), k, v

    def validate(  # noqa: C901,PLR0912
        self,
        *,
        allow_unknown_settings: bool = False,
    ) -> None:
        err_obj_not_a_dict = 'vault config is not a dict'
        err_non_str_service_name = (
            'vault config contains non-string service name {sv_name!r}'
        )
        err_not_a_dict = 'vault config entry {json_path_str} is not a dict'
        err_not_a_string = 'vault config entry {json_path_str} is not a string'
        err_not_an_int = 'vault config entry {json_path_str} is not an integer'
        err_unknown_setting = (
            'vault config entry {json_path_str} uses unknown setting {key!r}'
        )
        err_bad_number0 = 'vault config entry {json_path_str} is negative'
        err_bad_number1 = 'vault config entry {json_path_str} is not positive'

        kwargs: dict[str, Any] = {
            'allow_unknown_settings': allow_unknown_settings,
        }
        if not isinstance(self.maybe_config, dict):
            raise TypeError(err_obj_not_a_dict.format(**kwargs))
        if 'global' in self.maybe_config:
            o_global = self.maybe_config['global']
            if not isinstance(o_global, dict):
                kwargs['json_path_str'] = json_path(['global'])
                raise TypeError(err_not_a_dict.format(**kwargs))
        if not isinstance(self.maybe_config.get('services'), dict):
            kwargs['json_path_str'] = json_path(['services'])
            raise TypeError(err_not_a_dict.format(**kwargs))
        for sv_name, service in self.maybe_config['services'].items():
            if not isinstance(sv_name, str):
                kwargs['sv_name'] = sv_name
                raise TypeError(err_non_str_service_name.format(**kwargs))
            if not isinstance(service, dict):
                kwargs['json_path_str'] = json_path(['services', sv_name])
                raise TypeError(err_not_a_dict.format(**kwargs))
        for path, key, value in self.walk_subconfigs():
            kwargs['path'] = path
            kwargs['key'] = key
            kwargs['value'] = value
            kwargs['json_path_str'] = json_path([*path, key])
            # TODO(the-13th-letter): Rewrite using structural pattern
            # matching.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
            if key in {'key', 'phrase'}:
                if not isinstance(value, str):
                    raise TypeError(err_not_a_string.format(**kwargs))
            elif key == 'unicode_normalization_form' and path == ('global',):
                if not isinstance(value, str):
                    raise TypeError(err_not_a_string.format(**kwargs))
                if not allow_unknown_settings:
                    raise ValueError(err_unknown_setting.format(**kwargs))
            elif key == 'notes' and path != ('global',):
                if not isinstance(value, str):
                    raise TypeError(err_not_a_string.format(**kwargs))
            elif key in {
                'length',
                'repeat',
                'lower',
                'upper',
                'number',
                'space',
                'dash',
                'symbol',
            }:
                if not isinstance(value, int):
                    raise TypeError(err_not_an_int.format(**kwargs))
                if key == 'length' and value < 1:
                    raise ValueError(err_bad_number1.format(**kwargs))
                if key != 'length' and value < 0:
                    raise ValueError(err_bad_number0.format(**kwargs))
            elif not allow_unknown_settings:
                raise ValueError(err_unknown_setting.format(**kwargs))

    def clean_up_falsy_values(self) -> Iterator[CleanupStep]:  # noqa: C901
        obj = self.maybe_config
        if (
            not isinstance(obj, dict)
            or 'services' not in obj
            or not isinstance(obj['services'], dict)
        ):
            raise ValueError(
                self.INVALID_CONFIG_ERROR
            )  # pragma: no cover [failsafe]
        if 'global' in obj and not isinstance(obj['global'], dict):
            raise ValueError(
                self.INVALID_CONFIG_ERROR
            )  # pragma: no cover [failsafe]
        if not all(
            isinstance(service_obj, dict)
            for service_obj in obj['services'].values()
        ):
            raise ValueError(
                self.INVALID_CONFIG_ERROR
            )  # pragma: no cover [failsafe]

        def falsy(value: Any) -> bool:  # noqa: ANN401
            return not js_truthiness(value)

        def falsy_but_not_zero(value: Any) -> bool:  # noqa: ANN401
            return not js_truthiness(value) and not (
                isinstance(value, int) and value == 0
            )

        def falsy_but_not_string(value: Any) -> bool:  # noqa: ANN401
            return not js_truthiness(value) and value != ''  # noqa: PLC1901

        for path, key, value in self.walk_subconfigs():
            service_obj = self.traverse_path(path)
            # TODO(the-13th-letter): Rewrite using structural pattern
            # matching.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
            if key == 'phrase' and falsy_but_not_string(value):
                yield CleanupStep(
                    (*path, key), service_obj[key], 'replace', ''
                )
                service_obj[key] = ''
            elif key == 'notes' and falsy(value):
                yield CleanupStep(
                    (*path, key), service_obj[key], 'remove', None
                )
                service_obj.pop(key)
            elif key == 'key' and falsy(value):
                if path == ('global',):
                    yield CleanupStep(
                        (*path, key), service_obj[key], 'remove', None
                    )
                    service_obj.pop(key)
                else:
                    yield CleanupStep(
                        (*path, key), service_obj[key], 'replace', ''
                    )
                    service_obj[key] = ''
            elif key == 'length' and falsy(value):
                yield CleanupStep(
                    (*path, key), service_obj[key], 'replace', 20
                )
                service_obj[key] = 20
            elif key == 'repeat' and falsy_but_not_zero(value):
                yield CleanupStep((*path, key), service_obj[key], 'replace', 0)
                service_obj[key] = 0
            elif key in {
                'lower',
                'upper',
                'number',
                'space',
                'dash',
                'symbol',
            } and falsy_but_not_zero(value):
                yield CleanupStep(
                    (*path, key), service_obj[key], 'remove', None
                )
                service_obj.pop(key)


@overload
@deprecated(
    'allow_derivepassphrase_extensions argument is deprecated since v0.4.0, '
    'to be removed in v1.0: no extensions are defined'
)
def validate_vault_config(
    obj: Any,  # noqa: ANN401
    /,
    *,
    allow_derivepassphrase_extensions: bool,
    allow_unknown_settings: bool = False,
) -> None: ...


@overload
def validate_vault_config(
    obj: Any,  # noqa: ANN401
    /,
    *,
    allow_unknown_settings: bool = False,
) -> None: ...


def validate_vault_config(
    obj: Any,
    /,
    *,
    allow_unknown_settings: bool = False,
    allow_derivepassphrase_extensions: bool = _Omitted(),  # type: ignore[assignment]
) -> None:
    """Check that `obj` is a valid vault config.

    Args:
        obj:
            The object to test.
        allow_unknown_settings:
            If false, abort on unknown settings.
        allow_derivepassphrase_extensions:
            (Deprecated.)  Ignored since v0.4.0.

    Raises:
        TypeError:
            An entry in the vault config, or the vault config itself,
            has the wrong type.
        ValueError:
            An entry in the vault config is not allowed, or has a
            disallowed value.

    Warning: Deprecated argument
        **v0.4.0**:
            The `allow_derivepassphrase_extensions` keyword argument is
            deprecated, and will be removed in v1.0.  There are no
            specified `derivepassphrase` extensions.

    """
    # TODO(the-13th-letter): Remove this block in v1.0.
    # https://the13thletter.info/derivepassphrase/latest/upgrade-notes/#v1.0-allow-derivepassphrase-extensions
    # TODO(the-13th-letter): Add tests that trigger the deprecation warning,
    # then include this in coverage.
    if not isinstance(
        allow_derivepassphrase_extensions, _Omitted
    ):  # pragma: no cover [unused]
        warnings.warn(
            get_overloads(validate_vault_config)[0].__deprecated__,  # type: ignore[attr-defined]
            DeprecationWarning,
            stacklevel=2,
        )

    return _VaultConfigValidator(obj).validate(
        allow_unknown_settings=allow_unknown_settings
    )


def is_vault_config(obj: Any) -> TypeIs[VaultConfig]:  # noqa: ANN401
    """Check if `obj` is a valid vault config, according to typing.

    Args:
        obj: The object to test.

    Returns:
        True if this is a vault config, false otherwise.

    """  # noqa: DOC501
    try:
        validate_vault_config(
            obj,
            allow_unknown_settings=True,
        )
    except (TypeError, ValueError) as exc:
        if 'vault config ' not in str(exc):  # pragma: no cover [failsafe]
            raise
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
        if value in {None, False, 0, 0.0, ''}:  # noqa: B033
            return False
    except TypeError:
        # All falsy values are hashable, so this can't be falsy.
        return True
    return not (isinstance(value, float) and math.isnan(value))


class CleanupStep(NamedTuple):
    """A single executed step during vault config cleanup.

    Attributes:
        path:
            A sequence of object keys or array indices to navigate to
            the JSON value that was cleaned up.
        old_value:
            The old value.
        action:
            Either `'replace'` if `old_value` was replaced with
            `new_value`, or `'remove'` if `old_value` was removed.
        new_value:
            The new value.

    """

    path: Sequence[str | int]
    """"""
    old_value: Any
    """"""
    action: Literal['replace', 'remove']
    """"""
    new_value: Any
    """"""


def clean_up_falsy_vault_config_values(
    obj: Any,  # noqa: ANN401
) -> Sequence[CleanupStep] | None:
    """Convert falsy values in a vault config to correct types, in-place.

    Needed for compatibility with vault(1), which sometimes uses only
    truthiness checks.

    If vault(1) considered `obj` to be valid, then after clean up,
    `obj` will be valid as per [`validate_vault_config`][].

    Args:
        obj:
            A presumed valid vault configuration save for using falsy
            values of the wrong type.

    Returns:
        A list of 4-tuples `(key_tup, old_value, action, new_value)`,
        indicating the cleanup actions performed.  `key_tup` is
        a sequence of object keys and/or array indices indicating the
        JSON path to the leaf value that was cleaned up, `old_value` is
        the old value, `new_value` is the new value, and `action` is
        either `replace` (`old_value` was replaced with `new_value`) or
        `remove` (`old_value` was removed, and `new_value` is
        meaningless).

        If cleanup was never attempted because of an obviously invalid
        vault configuration, then `None` is returned, directly.

    """
    try:
        return list(_VaultConfigValidator(obj).clean_up_falsy_values())
    except ValueError:
        return None


# TODO(the-13th-letter): Use type variables local to each class.
# https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.11
T_Buffer = TypeVar('T_Buffer', bound=Buffer)
"""
A [`TypeVar`][] for classes implementing the [`Buffer`][] interface.

Warning:
    Non-public attribute, provided for didactical and educational
    purposes only.  Subject to change without notice, including
    removal.

"""


class SSHKeyCommentPair(NamedTuple, Generic[T_Buffer]):
    """SSH key plus comment pair.  For typing purposes.

    Attributes:
        key: SSH key.
        comment: SSH key comment.

    """

    key: T_Buffer
    """"""
    comment: T_Buffer
    """"""

    def toreadonly(self) -> SSHKeyCommentPair[bytes]:
        """Return a copy with read-only entries."""
        return SSHKeyCommentPair(
            key=bytes(self.key),
            comment=bytes(self.comment),
        )


class SSH_AGENTC(enum.Enum):  # noqa: N801
    """SSH agent protocol numbers: client requests.

    Attributes:
        REQUEST_IDENTITIES (int):
            List identities.  Expecting
            [`SSH_AGENT.IDENTITIES_ANSWER`][].
        SIGN_REQUEST (int):
            Sign data.  Expecting [`SSH_AGENT.SIGN_RESPONSE`][].
        ADD_IDENTITY (int):
            Add an (SSH2) identity.
        REMOVE_IDENTITY (int):
            Remove an (SSH2) identity.
        ADD_ID_CONSTRAINED (int):
            Add an (SSH2) identity, including key constraints.
        EXTENSION (int):
            Issue a named request that isn't part of the core agent
            protocol.  Expecting [`SSH_AGENT.EXTENSION_RESPONSE`][] or
            [`SSH_AGENT.EXTENSION_FAILURE`][] if the named request is
            supported, [`SSH_AGENT.FAILURE`][] otherwise.

    """

    REQUEST_IDENTITIES = 11
    """"""
    SIGN_REQUEST = 13
    """"""
    ADD_IDENTITY = 17
    """"""
    REMOVE_IDENTITY = 18
    """"""
    ADD_ID_CONSTRAINED = 25
    """"""
    EXTENSION = 27
    """"""


class SSH_AGENT(enum.Enum):  # noqa: N801
    """SSH agent protocol numbers: server replies.

    Attributes:
        FAILURE (int):
            Generic failure code.
        SUCCESS (int):
            Generic success code.
        IDENTITIES_ANSWER (int):
            Successful answer to [`SSH_AGENTC.REQUEST_IDENTITIES`][].
        SIGN_RESPONSE (int):
            Successful answer to [`SSH_AGENTC.SIGN_REQUEST`][].
        EXTENSION_FAILURE (int):
            Unsuccessful answer to [`SSH_AGENTC.EXTENSION`][].
        EXTENSION_RESPONSE (int):
            Successful answer to [`SSH_AGENTC.EXTENSION`][].

    """

    FAILURE = 5
    """"""
    SUCCESS = 6
    """"""
    IDENTITIES_ANSWER = 12
    """"""
    SIGN_RESPONSE = 14
    """"""
    EXTENSION_FAILURE = 28
    """"""
    EXTENSION_RESPONSE = 29
    """"""


class StoreroomKeyPair(NamedTuple, Generic[T_Buffer]):
    """A pair of AES256 keys, one for encryption and one for signing.

    Attributes:
        encryption_key:
            AES256 key, used for encryption with AES256-CBC (with PKCS#7
            padding).
        signing_key:
            AES256 key, used for signing with HMAC-SHA256.

    """

    encryption_key: T_Buffer
    """"""
    signing_key: T_Buffer
    """"""

    def toreadonly(self) -> StoreroomKeyPair[bytes]:
        """Return a copy with read-only entries."""
        return StoreroomKeyPair(
            encryption_key=bytes(self.encryption_key),
            signing_key=bytes(self.signing_key),
        )


class StoreroomMasterKeys(NamedTuple, Generic[T_Buffer]):
    """A triple of AES256 keys, for encryption, signing and hashing.

    Attributes:
        hashing_key:
            AES256 key, used for hashing with HMAC-SHA256 to derive
            a hash table slot for an item.
        encryption_key:
            AES256 key, used for encryption with AES256-CBC (with PKCS#7
            padding).
        signing_key:
            AES256 key, used for signing with HMAC-SHA256.

    """

    hashing_key: T_Buffer
    """"""
    encryption_key: T_Buffer
    """"""
    signing_key: T_Buffer
    """"""

    def toreadonly(self) -> StoreroomMasterKeys[bytes]:
        """Return a copy with read-only entries."""
        return StoreroomMasterKeys(
            hashing_key=bytes(self.hashing_key),
            encryption_key=bytes(self.encryption_key),
            signing_key=bytes(self.signing_key),
        )


class PEP508Extra(str, enum.Enum):
    """PEP 508 extras supported by `derivepassphrase`.

    Attributes:
        EXPORT:
            The necessary dependencies to allow the `export` subcommand
            to handle as many foreign configuration formats as possible.

    """

    EXPORT = 'export'
    """"""

    __str__ = str.__str__
    __format__ = str.__format__  # type: ignore[assignment]


class Feature(str, enum.Enum):
    """Optional features supported by `derivepassphrase`.

    Attributes:
        SSH_KEY:
            The `vault` subcommand supports using a master SSH key,
            instead of a master passphrase, if an SSH agent is running
            and the master SSH key is loaded into it.

            This feature requires Python support for the SSH agent's
            chosen communication channel technology.

    """

    SSH_KEY = 'master SSH key'
    """"""

    __str__ = str.__str__
    __format__ = str.__format__  # type: ignore[assignment]


class DerivationScheme(str, enum.Enum):
    """Derivation schemes provided by `derivepassphrase`.

    Attributes:
        VAULT:
            The derivation scheme used by James Coglan's `vault`.

    """

    VAULT = 'vault'
    """"""

    __str__ = str.__str__
    __format__ = str.__format__  # type: ignore[assignment]


class ForeignConfigurationFormat(str, enum.Enum):
    """Configuration formats supported by `derivepassphrase export`.

    Attributes:
        VAULT_STOREROOM:
            The vault "storeroom" format for the `export vault`
            subcommand.
        VAULT_V02:
            The vault-native "v0.2" format for the `export vault`
            subcommand.
        VAULT_V03:
            The vault-native "v0.3" format for the `export vault`
            subcommand.

    """

    VAULT_STOREROOM = 'vault storeroom'
    """"""
    VAULT_V02 = 'vault v0.2'
    """"""
    VAULT_V03 = 'vault v0.3'
    """"""

    __str__ = str.__str__
    __format__ = str.__format__  # type: ignore[assignment]


class ExportSubcommand(str, enum.Enum):
    """Subcommands provided by `derivepassphrase export`.

    Attributes:
        VAULT:
            The `export vault` subcommand.

    """

    VAULT = 'vault'
    """"""

    __str__ = str.__str__
    __format__ = str.__format__  # type: ignore[assignment]


class Subcommand(str, enum.Enum):
    """Subcommands provided by `derivepassphrase`.

    Attributes:
        EXPORT:
            The `export` subcommand.
        VAULT:
            The `vault` subcommand.

    """

    EXPORT = 'export'
    """"""
    VAULT = 'vault'
    """"""

    __str__ = str.__str__
    __format__ = str.__format__  # type: ignore[assignment]
