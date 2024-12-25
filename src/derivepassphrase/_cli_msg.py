# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-Licence-Identifier: MIT

"""Internal module.  Do not use.  Contains error strings and functions."""

from __future__ import annotations

import enum
import gettext
import inspect
import types
from typing import TYPE_CHECKING, NamedTuple

import derivepassphrase as dpp

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from typing_extensions import Any, Self

__author__ = dpp.__author__
__version__ = dpp.__version__

__all__ = ('PROG_NAME',)

PROG_NAME = 'derivepassphrase'
translation = gettext.translation(PROG_NAME, fallback=True)


class TranslatableString(NamedTuple):
    singular: str
    plural: str
    l10n_context: str
    translator_comments: str
    flags: frozenset[str]


def _prepare_translatable(
    msg: str,
    comments: str = '',
    context: str = '',
    plural_msg: str = '',
    *,
    flags: Iterable[str] = (),
) -> TranslatableString:
    msg = inspect.cleandoc(msg)
    plural_msg = inspect.cleandoc(plural_msg)
    context = context.strip()
    comments = inspect.cleandoc(comments)
    flags = (
        frozenset(f.strip() for f in flags)
        if not isinstance(flags, str)
        else frozenset({flags})
    )
    assert (
        '{' not in msg
        or bool(flags & {'python-brace-format', 'no-python-brace-format'})
    ), f'Missing flag for how to deal with brace in {msg!r}'
    assert (
        '%' not in msg
        or bool(flags & {'python-format', 'no-python-format'})
    ), f'Missing flag for how to deal with percent character in {msg!r}'
    return TranslatableString(msg, plural_msg, context, comments, flags)


class LogObject:

    def __init__(
        self,
        template: TranslatableString,
        args_dict: Mapping[str, Any] = types.MappingProxyType({}),
        /,
        **kwargs: Any,  # noqa: ANN401
    ) -> None:
        self.template = template
        self.kwargs = {**args_dict, **kwargs}
        self._rendered: str | None = None

    def __str__(self) -> str:
        if self._rendered is None:
            context = self.template.l10n_context
            template = self.template.singular
            if context is not None:
                template = translation.pgettext(context, template)
            else:
                template = translation.gettext(template)
            self._rendered = template.format(**self.kwargs)
        return self._rendered

    def maybe_without_filename(self) -> Self:
        if (
            self.kwargs.get('filename') is None
            and ': {filename!r}' in self.template.singular
        ):
            singular = ''.join(
                self.template.singular.split(': {filename!r}', 1)
            )
            plural = (
                ''.join(self.template.plural.split(': {filename!r}', 1))
                if self.template.plural
                else self.template.plural
            )
            return self.__class__(
                self.template._replace(singular=singular, plural=plural),
                self.kwargs,
            )
        return self

    @classmethod
    def InfoMsg(  # noqa: N802
        cls,
        msg_template: InfoMsgTemplate,
        args_dict: Mapping[str, Any] = types.MappingProxyType({}),
        /,
        **kwargs: Any,  # noqa: ANN401
    ) -> Self:
        return cls(msg_template.value, {**args_dict, **kwargs})

    @classmethod
    def WarnMsg(  # noqa: N802
        cls,
        msg_template: WarnMsgTemplate,
        args_dict: Mapping[str, Any] = types.MappingProxyType({}),
        /,
        **kwargs: Any,  # noqa: ANN401
    ) -> Self:
        return cls(msg_template.value, {**args_dict, **kwargs})

    @classmethod
    def ErrMsg(  # noqa: N802
        cls,
        msg_template: ErrMsgTemplate,
        args_dict: Mapping[str, Any] = types.MappingProxyType({}),
        /,
        **kwargs: Any,  # noqa: ANN401
    ) -> Self:
        return cls(msg_template.value, {**args_dict, **kwargs})


class InfoMsgTemplate(enum.Enum):
    CANNOT_LOAD_AS_VAULT_CONFIG = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "fmt" is a string such as "v0.2" or "storeroom",
        indicating the format which we tried to load the vault
        configuration as.
        """,
        msg='Cannot load {path!r} as a {fmt!s} vault configuration.',
        context='info message',
        flags='python-brace-format',
    )
    PIP_INSTALL_EXTRA = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message immediately follows an error message
        about a missing library that needs to be installed.  The Python
        Package Index (PyPI) supports declaring sets of optional
        dependencies as "extras", so users installing from PyPI can
        request reinstallation with a named "extra" being enabled.  This
        would then let the installer take care of the missing libraries
        automatically, hence this suggestion to PyPI users.
        """,
        msg='(For users installing from PyPI, see the {extra_name!r} extra.)',
        context='info message',
        flags='python-brace-format',
    )
    SUCCESSFULLY_MIGRATED = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This info message immediately follows the "Using
        deprecated v0.1-style ..." deprecation warning.
        """,
        msg='Successfully migrated to {path!r}.',
        context='info message',
        flags='python-brace-format',
    )


class WarnMsgTemplate(enum.Enum):
    EMPTY_SERVICE_NOT_SUPPORTED = _prepare_translatable(
        'An empty SERVICE is not supported by vault(1).  '
        'For compatibility, this will be treated as if SERVICE was not '
        'supplied, i.e., it will error out, or operate on global settings.',
        comments='',
        context='warning message',
    )
    EMPTY_SERVICE_SETTINGS_INACCESSIBLE = _prepare_translatable(
        f'An empty SERVICE is not supported by vault(1).  '
        f'The empty-string service settings will be '
        f'inaccessible and ineffective.  '
        f'To ensure that vault(1) and {PROG_NAME!s} see the settings, '
        f'move them into the "global" section.',
        comments='',
        context='warning message',
    )
    FAILED_TO_MIGRATE_CONFIG = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The error message is usually supplied by the
        operating system, e.g. ENOENT/"No such file or directory".
        """,
        msg='Failed to migrate to {path!r}: {error!s}: {filename!r}.',
        context='warning message',
        flags='python-brace-format',
    )
    GLOBAL_PASSPHRASE_INEFFECTIVE = _prepare_translatable(
        'Setting a global passphrase is ineffective '
        'because a key is also set.',
        comments='',
        context='warning message',
    )
    PASSPHRASE_NOT_NORMALIZED = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The key is a (vault) configuration key, in JSONPath
        syntax, typically "$.global" for the global passphrase or
        "$.services.service_name" or "$.services["service with spaces"]"
        for the services "service_name" and "service with spaces",
        respectively.  The form is one of the four Unicode normalization
        forms: NFC, NFD, NFKC, NFKD.

        The asterisks are not special.  Please feel free to substitute
        any other appropriate way to mark up emphasis of the word
        "displays".
        """,
        msg='The {key!s} passphrase is not {form!s}-normalized.  '
        'Its serialization as a byte string may not be what you '
        'expect it to be, even if it *displays* correctly.  '
        'Please make sure to double-check any derived '
        'passphrases for unexpected results.',
        context='warning message',
        flags='python-brace-format',
    )
    SERVICE_PASSPHRASE_INEFFECTIVE = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The key that is set need not necessarily be set at
        the service level; it may be a global key as well.
        """,
        msg='Setting a service passphrase is ineffective '
        'because a key is also set: {service!s}.',
        context='warning message',
        flags='python-brace-format',
    )
    STEP_REMOVE_INEFFECTIVE_VALUE = _prepare_translatable(
        'Removing ineffective setting {path!s} = {old!s}.',
        comments='',
        context='warning message',
        flags='python-brace-format',
    )
    STEP_REPLACE_INVALID_VALUE = _prepare_translatable(
        'Replacing invalid value {old!s} for key {path!s} with {new!s}.',
        comments='',
        context='warning message',
        flags='python-brace-format',
    )
    V01_STYLE_CONFIG = _prepare_translatable(
        'Using deprecated v0.1-style config file {old!r}, '
        'instead of v0.2-style {new!r}.  '
        'Support for v0.1-style config filenames will be removed in v1.0.',
        comments='',
        context='deprecation warning message',
        flags='python-brace-format',
    )
    V10_SUBCOMMAND_REQUIRED = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This deprecation warning may be issued at any
        level, i.e. we may actually be talking about subcommands, or
        sub-subcommands, or sub-sub-subcommands, etc., which is what the
        "here" is supposed to indicate.
        """,
        msg='A subcommand will be required here in v1.0.  '
        'See --help for available subcommands.  '
        'Defaulting to subcommand "vault".',
        context='deprecation warning message',
    )


class ErrMsgTemplate(enum.Enum):
    CANNOT_CONNECT_TO_AGENT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The error message is usually supplied by the
        operating system, e.g. ENOENT/"No such file or directory".
        """,
        msg='Cannot connect to the SSH agent: {error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_DECODEIMPORT_VAULT_SETTINGS = _prepare_translatable(
        msg='Cannot import vault settings: cannot decode JSON: {error!s}.',
        comments='',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_EXPORT_VAULT_SETTINGS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The error message is usually supplied by the
        operating system, e.g. ENOENT/"No such file or directory".
        """,
        msg='Cannot export vault settings: {error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_IMPORT_VAULT_SETTINGS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The error message is usually supplied by the
        operating system, e.g. ENOENT/"No such file or directory".
        """,
        msg='Cannot import vault settings: {error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_LOAD_USER_CONFIG = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The error message is usually supplied by the
        operating system, e.g. ENOENT/"No such file or directory".
        """,
        msg='Cannot load user config: {error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_LOAD_VAULT_SETTINGS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The error message is usually supplied by the
        operating system, e.g. ENOENT/"No such file or directory".
        """,
        msg='Cannot load vault settings: {error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_PARSE_AS_VAULT_CONFIG = _prepare_translatable(
        comments=r"""
        TRANSLATORS: Unlike the "Cannot load {path!r} as a {fmt!s} vault
        configuration." message, *this* error message is emitted when we
        have tried loading the path in each of our supported formats,
        and failed.  The user will thus see the above "Cannot load ..."
        warning message potentially multiple times, and this error
        message at the very bottom.
        """,
        msg='Cannot parse {path!r} as a valid vault-native '
        'configuration file/directory.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_STORE_VAULT_SETTINGS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The error message is usually supplied by the
        operating system, e.g. ENOENT/"No such file or directory".
        """,
        msg='Cannot store vault settings: {error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_UPDATE_SETTINGS_NO_SETTINGS = _prepare_translatable(
        msg='Cannot update {settings_type!s} settings '
        'without any given settings.  '
        'You must specify at least one of --lower, ..., '
        '--symbol, or --phrase or --key.',
        comments='',
        context='error message',
        flags='python-brace-format',
    )
    INVALID_VAULT_CONFIG = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This error message is a reaction to a validator
        function saying *that* the configuration is not valid, but not
        *how* it is not valid.  The configuration file is principally
        parsable, however.
        """,
        msg='Invalid vault config: {config!r}.',
        context='error message',
        flags='python-brace-format',
    )
    MISSING_MODULE = _prepare_translatable(
        'Cannot load the required Python module {module!r}.',
        comments='',
        context='error message',
        flags='python-brace-format',
    )
    NO_AF_UNIX = _prepare_translatable(
        'Cannot connect to an SSH agent because this Python version '
        'does not support UNIX domain sockets.',
        comments='',
        context='error message',
    )
    NO_KEY_OR_PHRASE = _prepare_translatable(
        'No passphrase or key was given in the configuration.  '
        'In this case, the --phrase or --key argument is required.',
        comments='',
        context='error message',
    )
    NO_SSH_AGENT_FOUND = _prepare_translatable(
        'Cannot find any running SSH agent because SSH_AUTH_SOCK is not set.',
        comments='',
        context='error message',
    )
    PARAMS_MUTUALLY_EXCLUSIVE = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The params are long-form command-line option names.
        Typical example: "--key is mutually exclusive with --phrase."
        """,
        msg='{param1!s} is mutually exclusive with {param2!s}.',
        context='error message',
        flags='python-brace-format',
    )
    PARAMS_NEEDS_SERVICE_OR_CONFIG = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The param is a long-form command-line option name,
        and "SERVICE" is the command-line argument for the (sometimes
        optional) service name.
        """,
        msg='{param!s} requires a SERVICE or --config.',
        context='error message',
        flags='python-brace-format',
    )
    PARAMS_NEEDS_SERVICE = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The param is a long-form command-line option name,
        and "SERVICE" is the command-line argument for the (sometimes
        optional) service name.
        """,
        msg='{param!s} requires a SERVICE.',
        context='error message',
        flags='python-brace-format',
    )
    PARAMS_NO_SERVICE = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The param is a long-form command-line option name,
        and "SERVICE" is the command-line argument for the (sometimes
        optional) service name.
        """,
        msg='{param!s} does not take a SERVICE argument.',
        context='error message',
        flags='python-brace-format',
    )
    SERVICE_REQUIRED = _prepare_translatable(
        'Generating a passphrase requires a SERVICE.',
        comments='',
        context='error message',
    )
    SSH_KEY_NOT_LOADED = _prepare_translatable(
        'The requested SSH key is not loaded into the agent.',
        comments='',
        context='error message',
    )
    USER_ABORTED_EDIT = _prepare_translatable(
        'Not saving any new notes: the user aborted the request.',
        comments='',
        context='error message',
    )
    USER_ABORTED_PASSPHRASE = _prepare_translatable(
        'No passphrase was given; the user aborted the request.',
        comments='',
        context='error message',
    )
    USER_ABORTED_SSH_KEY_SELECTION = _prepare_translatable(
        'No SSH key was selected; the user aborted the request.',
        comments='',
        context='error message',
    )
    USER_CONFIG_INVALID = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The error message is usually supplied by the
        operating system, e.g. ENOENT/"No such file or directory".
        """,
        msg='The user configuration file is invalid.  '
        '{error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
