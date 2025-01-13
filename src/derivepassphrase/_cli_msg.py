# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-Licence-Identifier: MIT

"""Internal module.  Do not use.  Contains error strings and functions."""

from __future__ import annotations

import contextlib
import datetime
import enum
import gettext
import inspect
import os
import string
import sys
import textwrap
import types
from typing import TYPE_CHECKING, NamedTuple, TextIO, Union, cast

from typing_extensions import TypeAlias, override

import derivepassphrase as dpp

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping, Sequence

    from typing_extensions import Any, Self

__author__ = dpp.__author__
__version__ = dpp.__version__

__all__ = ('PROG_NAME',)

PROG_NAME = 'derivepassphrase'


def load_translations(
    localedirs: list[str] | None = None,
    languages: Sequence[str] | None = None,
    class_: type[gettext.NullTranslations] | None = None,
) -> gettext.NullTranslations:  # pragma: no cover
    """Load a translation catalog for derivepassphrase.

    Runs [`gettext.translation`][] under the hood for multiple locale
    directories.  `fallback=True` is implied.

    Args:
        localedirs:
            A list of directories to run [`gettext.translation`][]
            against.  Defaults to `$XDG_DATA_HOME/locale` (usually
            `~/.local/share/locale`), `{sys.prefix}/share/locale` and
            `{sys.base_prefix}/share/locale` if not given.
        languages:
            Passed directly to [`gettext.translation`][].
        class_:
            Passed directly to [`gettext.translation`][].

    Returns:
        A (potentially dummy) translation catalog.

    """
    if localedirs is None:
        if sys.platform.startswith('win'):
            xdg_data_home = os.environ.get(
                'APPDATA',
                os.path.expanduser('~'),
            )
        elif os.environ.get('XDG_DATA_HOME'):
            xdg_data_home = os.environ['XDG_DATA_HOME']
        else:
            xdg_data_home = os.path.join(
                os.path.expanduser('~'), '.local', 'share'
            )
        localedirs = [
            os.path.join(xdg_data_home, 'locale'),
            os.path.join(sys.prefix, 'share', 'locale'),
            os.path.join(sys.base_prefix, 'share', 'locale'),
        ]
    for localedir in localedirs:
        with contextlib.suppress(OSError):
            return gettext.translation(
                PROG_NAME,
                localedir=localedir,
                languages=languages,
                class_=class_,
            )
    return gettext.NullTranslations()


translation = load_translations()
_debug_translation_message_cache: dict[tuple[str, str], MsgTemplate] = {}


class DebugTranslations(gettext.NullTranslations):
    """A debug object indicating which known message is being requested.

    Each call to the `*gettext` methods will return the enum name if the
    message is a known translatable message for the `derivepassphrase`
    command-line interface, or the message itself otherwise.

    """

    @staticmethod
    def _load_cache() -> None:
        cache = _debug_translation_message_cache
        for enum_class in MSG_TEMPLATE_CLASSES:
            for member in enum_class.__members__.values():
                value = cast('TranslatableString', member.value)
                value2 = value.maybe_without_filename()
                for v in {value, value2}:
                    singular = v.singular
                    plural = v.plural
                    context = v.l10n_context
                    cache.setdefault((context, singular), member)
                    if plural:
                        cache.setdefault((context, plural), member)

    @classmethod
    def _locate_message(
        cls,
        message: str,
        /,
        *,
        context: str = '',
        message_plural: str = '',
        n: int = 1,
    ) -> str:
        try:
            enum_value = _debug_translation_message_cache[context, message]
        except KeyError:
            return message if not message_plural or n == 1 else message_plural
        return cls._format_enum_name_maybe_with_fields(
            enum_name=str(enum_value),
            ts=cast('TranslatableString', enum_value.value),
        )

    @staticmethod
    def _format_enum_name_maybe_with_fields(
        enum_name: str,
        ts: TranslatableString,
    ) -> str:
        formatter = string.Formatter()
        fields: dict[str, int] = {}
        for _lit, field, _spec, _conv in formatter.parse(ts.singular):
            if field is not None and field not in fields:
                fields[field] = len(fields)
        sorted_fields = [
            f'{field}={{{field}!r}}'
            for field in sorted(fields.keys(), key=fields.__getitem__)
        ]
        return (
            '{!s}({})'.format(enum_name, ', '.join(sorted_fields))
            if sorted_fields
            else str(enum_name)
        )

    @override
    def gettext(
        self,
        message: str,
        /,
    ) -> str:  # pragma: no cover
        return self._locate_message(message)

    @override
    def ngettext(
        self,
        msgid1: str,
        msgid2: str,
        n: int,
        /,
    ) -> str:  # pragma: no cover
        return self._locate_message(msgid1, message_plural=msgid2, n=n)

    @override
    def pgettext(
        self,
        context: str,
        message: str,
        /,
    ) -> str:
        return self._locate_message(message, context=context)

    @override
    def npgettext(
        self,
        context: str,
        msgid1: str,
        msgid2: str,
        n: int,
        /,
    ) -> str:  # pragma: no cover
        return self._locate_message(
            msgid1,
            context=context,
            message_plural=msgid2,
            n=n,
        )


class TranslatableString(NamedTuple):
    singular: str
    plural: str
    l10n_context: str
    translator_comments: str
    flags: frozenset[str]

    @staticmethod
    def _maybe_rewrap(
        string: str,
        /,
        *,
        fix_sentence_endings: bool = True,
    ) -> str:
        string = inspect.cleandoc(string)
        if not any(s.strip() == '\b' for s in string.splitlines()):
            string = '\n'.join(
                textwrap.wrap(
                    string,
                    width=float('inf'),  # type: ignore[arg-type]
                    fix_sentence_endings=fix_sentence_endings,
                )
            )
        else:
            string = ''.join(
                s
                for s in string.splitlines(True)  # noqa: FBT003
                if s.strip() != '\b'
            )
        return string

    def maybe_without_filename(self) -> Self:
        """Return a new translatable string without the "filename" field.

        Only acts upon translatable strings containing the exact
        contents `": {filename!r}"`.  The specified part will be
        removed.  This is correct usage in English for messages like
        `"Cannot open file: {error!s}: {filename!r}."`, but not
        necessarily in other languages.

        """
        filename_str = ': {filename!r}'
        ret = self
        a, sep1, b = self.singular.partition(filename_str)
        c, sep2, d = self.plural.partition(filename_str)
        if sep1:
            ret = ret._replace(singular=(a + b))
        if sep2:
            ret = ret._replace(plural=(c + d))
        return ret

    def rewrapped(self) -> Self:
        """Return a rewrapped version of self.

        Normalizes all parts assumed to contain English prose.

        """
        msg = self._maybe_rewrap(self.singular, fix_sentence_endings=True)
        plural = self._maybe_rewrap(self.plural, fix_sentence_endings=True)
        context = self.l10n_context.strip()
        comments = self._maybe_rewrap(
            self.translator_comments, fix_sentence_endings=False
        )
        return self._replace(
            singular=msg,
            plural=plural,
            l10n_context=context,
            translator_comments=comments,
        )

    def with_comments(self, comments: str, /) -> Self:
        """Add or replace the string's translator comments.

        The comments are assumed to contain English prose, and will be
        normalized.

        Returns:
            A new [`TranslatableString`][] with the specified comments.

        """
        if not comments.lstrip().startswith(  # pragma: no cover
            'TRANSLATORS:'
        ):
            comments = 'TRANSLATORS: ' + comments.lstrip()
        comments = self._maybe_rewrap(comments, fix_sentence_endings=False)
        return self._replace(translator_comments=comments)

    def validate_flags(self, *extra_flags: str) -> Self:
        """Add all flags, then validate them against the string.

        Returns:
            A new [`TranslatableString`][] with the extra flags added,
            and all flags validated.

        Raises:
            ValueError:
                The flags failed to validate.  See the exact error
                message for details.

        """
        all_flags = frozenset(
            f.strip() for f in self.flags.union(extra_flags)
        )
        if '{' in self.singular and not bool(
            all_flags & {'python-brace-format', 'no-python-brace-format'}
        ):
            msg = (
                f'Missing flag for how to deal with brace character '
                f'in {self.singular!r}'
            )
            raise ValueError(msg)
        if '%' in self.singular and not bool(
            all_flags & {'python-format', 'no-python-format'}
        ):
            msg = (
                f'Missing flag for how to deal with percent character '
                f'in {self.singular!r}'
            )
            raise ValueError(msg)
        if (
            all_flags & {'python-format', 'python-brace-format'}
            and '%' not in self.singular
            and '{' not in self.singular
        ):
            msg = f'Missing format string parameters in {self.singular!r}'
            raise ValueError(msg)
        return self._replace(flags=all_flags)


def _prepare_translatable(
    msg: str,
    comments: str = '',
    context: str = '',
    plural_msg: str = '',
    *,
    flags: Iterable[str] = (),
) -> TranslatableString:
    return translatable(
        context, msg, plural=plural, comments=comments, flags=flags
    )


def translatable(
    context: str,
    single: str,
    /,
    flags: Iterable[str] = (),
    plural: str = '',
    comments: str = '',
) -> TranslatableString:
    """Return a [`TranslatableString`][] with validated parts.

    This factory function is really only there to make the enum
    definitions more readable.

    """
    flags = (
        frozenset(flags)
        if not isinstance(flags, str)
        else frozenset({flags})
    )
    return (
        TranslatableString(context, single, plural=plural, flags=flags)
        .rewrapped()
        .with_comments(comments)
        .validate_flags()
    )


class TranslatedString:
    def __init__(
        self,
        template: (
            str
            | TranslatableString
            | MsgTemplate
        ),
        args_dict: Mapping[str, Any] = types.MappingProxyType({}),
        /,
        **kwargs: Any,  # noqa: ANN401
    ) -> None:
        if isinstance(template, MSG_TEMPLATE_CLASSES):
            template = cast('TranslatableString', template.value)
        self.template = template
        self.kwargs = {**args_dict, **kwargs}
        self._rendered: str | None = None

    def __bool__(self) -> bool:
        return bool(str(self))

    def __eq__(self, other: object) -> bool:  # pragma: no cover
        return str(self) == other

    def __hash__(self) -> int:  # pragma: no cover
        return hash(str(self))

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f'{self.__class__.__name__}({self.template!r}, '
            f'{dict(self.kwargs)!r})'
        )

    def __str__(self) -> str:
        if self._rendered is None:
            # raw str support is currently unneeded, so excluded from coverage
            if isinstance(self.template, str):  # pragma: no cover
                context = None
                template = self.template
            else:
                context = self.template.l10n_context
                template = self.template.singular
            if context is not None:
                template = translation.pgettext(context, template)
            else:  # pragma: no cover
                template = translation.gettext(template)
            kwargs = {
                k: str(v) if isinstance(v, TranslatedString) else v
                for k, v in self.kwargs.items()
            }
            self._rendered = template.format(**kwargs)
        return self._rendered

    def maybe_without_filename(self) -> Self:
        """Return a new string without the "filename" field.

        Only acts upon translated strings containing the exact contents
        `": {filename!r}"`.  The specified part will be removed.  This
        acts upon the string *before* translation, i.e., the string
        without the filename will be used as a translation base.

        """
        new_template = (
            self.template.maybe_without_filename()
            if not isinstance(self.template, str)
            else self.template
        )
        if (
            not isinstance(new_template, str)
            and self.kwargs.get('filename') is None
            and new_template != self.template
        ):
            return self.__class__(new_template, self.kwargs)
        return self


class Label(enum.Enum):
    DEPRECATION_WARNING_LABEL = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This is a short label that will be prepended to
        a warning message, e.g., "Deprecation warning: A subcommand will
        be required in v1.0."
        """,
        msg='Deprecation warning',
        context='diagnostic label',
    )
    WARNING_LABEL = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This is a short label that will be prepended to
        a warning message, e.g., "Warning: An empty service name is not
        supported by vault(1)."
        """,
        msg='Warning',
        context='diagnostic label',
    )
    CANNOT_UPDATE_SETTINGS_METAVAR_SETTINGS_TYPE_GLOBAL = (
        _prepare_translatable(
            comments=r"""
            TRANSLATORS: This is one of two values of the settings_type
            metavar used in the CANNOT_UPDATE_SETTINGS_NO_SETTINGS
            entry.  It is only used there.  The full sentence then
            reads: "Cannot update the global settings without any given
            settings."
            """,
            msg='global settings',
            context='diagnostic label (metavar value)',
        )
    )
    CANNOT_UPDATE_SETTINGS_METAVAR_SETTINGS_TYPE_SERVICE = (
        _prepare_translatable(
            comments=r"""
            TRANSLATORS: This is one of two values of the settings_type
            metavar used in the CANNOT_UPDATE_SETTINGS_NO_SETTINGS
            entry.  It is only used there.  The full sentence then
            reads: "Cannot update the service-specific settings without
            any given settings."
            """,
            msg='service-specific settings',
            context='diagnostic label (metavar value)',
        )
    )
    DERIVEPASSPHRASE_01 = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This is the first paragraph of the command help
        text, but it also appears (in truncated form, if necessary) as
        one-line help text for this command.  The translation should
        thus be as meaningful as possible even if truncated.
        """,
        msg="""
        Derive a strong passphrase, deterministically, from a master secret.
        """,
        context='help text (long form)',
    )
    DERIVEPASSPHRASE_02 = _prepare_translatable(
        msg="""
        The currently implemented subcommands are "vault" (for the
        scheme used by vault) and "export" (for exporting foreign
        configuration data).  See the respective `--help` output for
        instructions.  If no subcommand is given, we default to "vault".
        """,
        comments='',
        context='help text (long form)',
    )
    DERIVEPASSPHRASE_03 = _prepare_translatable(
        msg="""
        Deprecation notice: Defaulting to "vault" is deprecated.
        Starting in v1.0, the subcommand must be specified explicitly.
        """,
        comments='',
        context='help text (long form)',
    )
    DERIVEPASSPHRASE_EPILOG_01 = _prepare_translatable(
        msg=r"""
        Configuration is stored in a directory according to the
        `DERIVEPASSPHRASE_PATH` variable, which defaults to
        `~/.derivepassphrase` on UNIX-like systems and
        `C:\Users\<user>\AppData\Roaming\Derivepassphrase` on Windows.
        """,
        comments='',
        context='help text (long form)',
    )
    DERIVEPASSPHRASE_EXPORT_01 = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This is the first paragraph of the command help
        text, but it also appears (in truncated form, if necessary) as
        one-line help text for this command.  The translation should
        thus be as meaningful as possible even if truncated.
        """,
        msg="""
        Export a foreign configuration to standard output.
        """,
        context='help text (long form)',
    )
    DERIVEPASSPHRASE_EXPORT_02 = _prepare_translatable(
        msg="""
        The only available subcommand is "vault", which implements the
        vault-native configuration scheme.  If no subcommand is given,
        we default to "vault".
        """,
        comments='',
        context='help text (long form)',
    )
    DERIVEPASSPHRASE_EXPORT_03 = DERIVEPASSPHRASE_03
    DERIVEPASSPHRASE_EXPORT_VAULT_01 = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This is the first paragraph of the command help
        text, but it also appears (in truncated form, if necessary) as
        one-line help text for this command.  The translation should
        thus be as meaningful as possible even if truncated.
        """,
        msg="""
        Export a vault-native configuration to standard output.
        """,
        context='help text (long form)',
    )
    DERIVEPASSPHRASE_EXPORT_VAULT_02 = _prepare_translatable(
        msg="""
        Depending on the configuration format, {path_metavar!s} may
        either be a file or a directory.  We support the vault "v0.2",
        "v0.3" and "storeroom" formats.
        """,
        comments='',
        context='help text (long form)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_EXPORT_VAULT_03 = _prepare_translatable(
        msg="""
        If {path_metavar!s} is explicitly given as `VAULT_PATH`, then
        use the `VAULT_PATH` environment variable to determine the
        correct path.  (Use `./VAULT_PATH` or similar to indicate
        a file/directory actually named `VAULT_PATH`.)
        """,
        comments='',
        context='help text (long form)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_01 = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This is the first paragraph of the command help
        text, but it also appears (in truncated form, if necessary) as
        one-line help text for this command.  The translation should
        thus be as meaningful as possible even if truncated.
        """,
        msg="""
        Derive a passphrase using the vault derivation scheme.
        """,
        context='help text (long form)',
    )
    DERIVEPASSPHRASE_VAULT_02 = _prepare_translatable(
        msg="""
        If operating on global settings, or importing/exporting
        settings, then {service_metavar!s} must be omitted.  Otherwise
        it is required.
        """,
        comments='',
        context='help text (long form)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_EPILOG_01 = _prepare_translatable(
        msg="""
        WARNING: There is NO WAY to retrieve the generated passphrases
        if the master passphrase, the SSH key, or the exact passphrase
        settings are lost, short of trying out all possible
        combinations.  You are STRONGLY advised to keep independent
        backups of the settings and the SSH key, if any.
        """,
        comments='',
        context='help text (long form)',
    )
    DERIVEPASSPHRASE_VAULT_EPILOG_02 = _prepare_translatable(
        msg="""
        The configuration is NOT encrypted, and you are STRONGLY
        discouraged from using a stored passphrase.
        """,
        comments='',
        context='help text (long form)',
    )
    DEPRECATED_COMMAND_LABEL = _prepare_translatable(
        comments=r"""
        TRANSLATORS: We use this format string to indicate, at the
        beginning of a command's help text, that this command is
        deprecated.
        """,
        msg='(Deprecated) {text}',
        context='help text (long form, label)',
        flags='python-brace-format',
    )
    DEBUG_OPTION_HELP_TEXT = _prepare_translatable(
        'also emit debug information (implies --verbose)',
        comments='',
        context='help text (option one-line description)',
    )
    EXPORT_VAULT_FORMAT_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The defaults_hint is
        Label.EXPORT_VAULT_FORMAT_DEFAULTS_HELP_TEXT, the metavar is
        Label.EXPORT_VAULT_FORMAT_METAVAR_FMT.
        """,
        msg=r"""
        try the following storage format {metavar!s}; may be
        specified multiple times, formats will be tried in order
        {defaults_hint!s}
        """,
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    EXPORT_VAULT_FORMAT_DEFAULTS_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: See EXPORT_VAULT_FORMAT_HELP_TEXT.  The format
        names/labels "v0.3", "v0.2" and "storeroom" should not be
        translated.
        """,
        msg=r"""
        (default: v0.3, v0.2, storeroom)
        """,
        context='help text (option one-line description)',
    )
    EXPORT_VAULT_KEY_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The defaults_hint is
        Label.EXPORT_VAULT_KEY_DEFAULTS_HELP_TEXT, the metavar is
        Label.EXPORT_VAULT_KEY_METAVAR_K.
        """,
        msg=r"""
        use {metavar!s} as the storage master key {defaults_hint!s}
        """,
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    EXPORT_VAULT_KEY_DEFAULTS_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: See EXPORT_VAULT_KEY_HELP_TEXT.
        """,
        msg=r"""
        (default: check the `VAULT_KEY`, `LOGNAME`, `USER`, or
        `USERNAME` environment variables)
        """,
        context='help text (option one-line description)',
    )
    HELP_OPTION_HELP_TEXT = _prepare_translatable(
        'show this help text, then exit',
        comments='',
        context='help text (option one-line description)',
    )
    QUIET_OPTION_HELP_TEXT = _prepare_translatable(
        'suppress even warnings, emit only errors',
        comments='',
        context='help text (option one-line description)',
    )
    VERBOSE_OPTION_HELP_TEXT = _prepare_translatable(
        'emit extra/progress information to standard error',
        comments='',
        context='help text (option one-line description)',
    )
    VERSION_OPTION_HELP_TEXT = _prepare_translatable(
        'show applicable version information, then exit',
        comments='',
        context='help text (option one-line description)',
    )

    DERIVEPASSPHRASE_VAULT_PHRASE_HELP_TEXT = _prepare_translatable(
        msg='prompt for a master passphrase',
        comments='',
        context='help text (option one-line description)',
    )
    DERIVEPASSPHRASE_VAULT_KEY_HELP_TEXT = _prepare_translatable(
        msg='select a suitable SSH key from the SSH agent',
        comments='',
        context='help text (option one-line description)',
    )
    DERIVEPASSPHRASE_VAULT_LENGTH_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The metavar is
        Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.
        """,
        msg='ensure a passphrase length of {metavar!s} characters',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_REPEAT_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The metavar is
        Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.
        """,
        msg='forbid any run of {metavar!s} identical characters',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_LOWER_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The metavar is
        Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.
        """,
        msg='ensure at least {metavar!s} lowercase characters',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_UPPER_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The metavar is
        Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.
        """,
        msg='ensure at least {metavar!s} uppercase characters',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_NUMBER_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The metavar is
        Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.
        """,
        msg='ensure at least {metavar!s} digits',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_SPACE_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The metavar is
        Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.
        """,
        msg='ensure at least {metavar!s} spaces',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_DASH_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The metavar is
        Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.
        """,
        msg='ensure at least {metavar!s} "-" or "_" characters',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_SYMBOL_HELP_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The metavar is
        Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.
        """,
        msg='ensure at least {metavar!s} symbol characters',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )

    DERIVEPASSPHRASE_VAULT_NOTES_HELP_TEXT = _prepare_translatable(
        msg='spawn an editor to edit notes for {service_metavar!s}',
        comments='',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_CONFIG_HELP_TEXT = _prepare_translatable(
        msg='save the given settings for {service_metavar!s}, or global',
        comments='',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_DELETE_HELP_TEXT = _prepare_translatable(
        msg='delete the settings for {service_metavar!s}',
        comments='',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_DELETE_GLOBALS_HELP_TEXT = _prepare_translatable(
        msg='delete the global settings',
        comments='',
        context='help text (option one-line description)',
    )
    DERIVEPASSPHRASE_VAULT_DELETE_ALL_HELP_TEXT = _prepare_translatable(
        msg='delete all settings',
        comments='',
        context='help text (option one-line description)',
    )
    DERIVEPASSPHRASE_VAULT_EXPORT_HELP_TEXT = _prepare_translatable(
        comments="""
        TRANSLATORS: The metavar is
        Label.STORAGE_MANAGEMENT_METAVAR_SERVICE.
        """,
        msg='export all saved settings to {metavar!s}',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_IMPORT_HELP_TEXT = _prepare_translatable(
        comments="""
        TRANSLATORS: The metavar is
        Label.STORAGE_MANAGEMENT_METAVAR_SERVICE.
        """,
        msg='import saved settings from {metavar!s}',
        context='help text (option one-line description)',
        flags='python-brace-format',
    )
    DERIVEPASSPHRASE_VAULT_OVERWRITE_HELP_TEXT = _prepare_translatable(
        comments="""
        TRANSLATORS: The corresponding option is displayed as
        "--overwrite-existing / --merge-existing", so you may want to
        hint that the default (merge) is the second of those options.
        """,
        msg='overwrite or merge (default) the existing configuration',
        context='help text (option one-line description)',
    )
    DERIVEPASSPHRASE_VAULT_UNSET_HELP_TEXT = _prepare_translatable(
        comments="""
        TRANSLATORS: The corresponding option is displayed as
        "--unset=phrase|key|...|symbol", so the "given setting" is
        referring to "phrase", "key", "lower", ..., or "symbol",
        respectively.  "with --config" here means that the user must
        also specify "--config" for this option to have any effect.
        """,
        msg="""
        with --config, also unsets the given setting; may be specified
        multiple times
        """,
        context='help text (option one-line description)',
    )
    DERIVEPASSPHRASE_VAULT_EXPORT_AS_HELP_TEXT = _prepare_translatable(
        comments="""
        TRANSLATORS: The corresponding option is displayed as
        "--export-as=json|sh", so json refers to the JSON format
        (default) and sh refers to the POSIX sh format.
        """,
        msg='when exporting, export as JSON (default) or POSIX sh',
        context='help text (option one-line description)',
    )

    EXPORT_VAULT_FORMAT_METAVAR_FMT = _prepare_translatable(
        msg='FMT',
        comments='',
        context='help text, metavar (export vault subcommand)',
    )
    EXPORT_VAULT_KEY_METAVAR_K = _prepare_translatable(
        comments=r"""
        TRANSLATORS: See Label.EXPORT_VAULT_KEY_HELP_TEXT.
        """,
        msg='K',
        context='help text, metavar (export vault subcommand)',
    )
    EXPORT_VAULT_METAVAR_PATH = _prepare_translatable(
        comments=r"""
        TRANSLATORS: Used as "path_metavar" in
        Label.DERIVEPASSPHRASE_EXPORT_VAULT_02 and others.
        """,
        msg='PATH',
        context='help text, metavar (export vault subcommand)',
    )
    PASSPHRASE_GENERATION_METAVAR_NUMBER = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This metavar is also used in a matching epilog.
        """,
        msg='NUMBER',
        context='help text, metavar (passphrase generation group)',
    )
    STORAGE_MANAGEMENT_METAVAR_PATH = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This metavar is also used in multiple one-line help
        texts.
        """,
        msg='PATH',
        context='help text, metavar (storage management group)',
    )
    VAULT_METAVAR_SERVICE = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This metavar is also used in multiple one-line help
        texts, as "service_metavar".
        """,
        msg='SERVICE',
        context='help text, metavar (vault subcommand)',
    )
    CONFIGURATION_EPILOG = _prepare_translatable(
        'Use $VISUAL or $EDITOR to configure the spawned editor.',
        comments='',
        context='help text, option group epilog (configuration group)',
    )
    PASSPHRASE_GENERATION_EPILOG = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The metavar is
        Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.
        """,
        msg=r"""
        Use {metavar!s}=0 to exclude a character type from the output.
        """,
        context='help text, option group epilog (passphrase generation group)',
        flags='python-brace-format',
    )
    STORAGE_MANAGEMENT_EPILOG = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The metavar is
        Label.STORAGE_MANAGEMENT_METAVAR_PATH.
        """,
        msg=r"""
        Using "-" as {metavar!s} for standard input/standard output
        is supported.
        """,
        context='help text, option group epilog (storage management group)',
        flags='python-brace-format',
    )
    COMMANDS_LABEL = _prepare_translatable(
        'Commands', comments='', context='help text, option group name'
    )
    COMPATIBILITY_OPTION_LABEL = _prepare_translatable(
        'Compatibility and extension options',
        comments='',
        context='help text, option group name',
    )
    CONFIGURATION_LABEL = _prepare_translatable(
        'Configuration', comments='', context='help text, option group name'
    )
    LOGGING_LABEL = _prepare_translatable(
        'Logging', comments='', context='help text, option group name'
    )
    OPTIONS_LABEL = _prepare_translatable(
        'Options', comments='', context='help text, option group name'
    )
    OTHER_OPTIONS_LABEL = _prepare_translatable(
        'Other options', comments='', context='help text, option group name'
    )
    PASSPHRASE_GENERATION_LABEL = _prepare_translatable(
        'Passphrase generation',
        comments='',
        context='help text, option group name',
    )
    STORAGE_MANAGEMENT_LABEL = _prepare_translatable(
        'Storage management',
        comments='',
        context='help text, option group name',
    )
    VERSION_INFO_TEXT = _prepare_translatable(
        msg=r"""
        {PROG_NAME!s} {__version__}
        """,  # noqa: RUF027
        comments='',
        context='help text, version info text',
        flags='python-brace-format',
    )
    CONFIRM_THIS_CHOICE_PROMPT_TEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: There is no support for "yes" or "no" in other
        languages than English, so it is advised that your translation
        makes it clear that only the strings "y", "yes", "n" or "no" are
        supported, even if the prompt becomes a bit longer.
        """,
        msg='Confirm this choice? (y/N)',
        context='interactive prompt',
    )
    SUITABLE_SSH_KEYS_LABEL = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This label is the heading of the list of suitable
        SSH keys.
        """,
        msg='Suitable SSH keys:',
        context='interactive prompt',
    )
    YOUR_SELECTION_PROMPT_TEXT = _prepare_translatable(
        'Your selection? (1-{n}, leave empty to abort)',
        comments='',
        context='interactive prompt',
        flags='python-brace-format',
    )


class DebugMsgTemplate(enum.Enum):
    BUCKET_ITEM_FOUND = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "storeroom"-type configuration directories.  The
        system stores entries in different "buckets" of a hash table.
        Here, we report on a single item (path and value) we discovered
        after decrypting the whole bucket.  (We ensure the path and
        value are printable as-is.)
        """,
        msg='Found bucket item: {path} -> {value}',
        context='debug message',
        flags='python-brace-format',
    )
    DECRYPT_BUCKET_ITEM_INFO = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "AES256-CBC" and "PKCS#7" are, in essence, names of
        formats, and should not be translated.  "IV" means
        "initialization vector", and is specifically a cryptographic
        term, as are "plaintext" and "ciphertext".
        """,
        msg="""
        Decrypt bucket item contents:

          \b
          Encryption key (master key): {enc_key}
          Encryption cipher: AES256-CBC with PKCS#7 padding
          Encryption IV: {iv}
          Encrypted ciphertext: {ciphertext}
          Plaintext: {plaintext}
        """,
        context='debug message',
        flags='python-brace-format',
    )
    DECRYPT_BUCKET_ITEM_KEY_INFO = _prepare_translatable(
        msg="""
        Decrypt bucket item:

          \b
          Plaintext: {plaintext}
          Encryption key (master key): {enc_key}
          Signing key (master key): {sign_key}
        """,
        comments='',
        context='debug message',
        flags='python-brace-format',
    )
    DECRYPT_BUCKET_ITEM_MAC_INFO = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The MAC stands for "message authentication code",
        which guarantees the authenticity of the message to anyone who
        holds the corresponding key, similar to a digital signature.
        The acronym "MAC" is assumed to be well-known to the English
        target audience, or at least discoverable by them; they *are*
        asking for debug output, after all.  Please use your judgement
        as to whether to translate this term or not, expanded or not.
        """,
        msg="""
        Decrypt bucket item contents:

          \b
          MAC key: {sign_key}
          Authenticated content: {ciphertext}
          Claimed MAC value: {claimed_mac}
          Computed MAC value: {actual_mac}
        """,
        context='debug message',
        flags='python-brace-format',
    )
    DECRYPT_BUCKET_ITEM_SESSION_KEYS_INFO = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "AES256-CBC" and "PKCS#7" are, in essence, names of
        formats, and should not be translated.  "IV" means
        "initialization vector", and is specifically a cryptographic
        term, as are "plaintext" and "ciphertext".
        """,
        msg="""
        Decrypt bucket item session keys:

          \b
          Encryption key (master key): {enc_key}
          Encryption cipher: AES256-CBC with PKCS#7 padding
          Encryption IV: {iv}
          Encrypted ciphertext: {ciphertext}
          Plaintext: {plaintext}
          Parsed plaintext: {code}
        """,
        context='debug message',
        flags='python-brace-format',
    )
    DECRYPT_BUCKET_ITEM_SESSION_KEYS_MAC_INFO = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The MAC stands for "message authentication code",
        which guarantees the authenticity of the message to anyone who
        holds the corresponding key, similar to a digital signature.
        The acronym "MAC" is assumed to be well-known to the English
        target audience, or at least discoverable by them; they *are*
        asking for debug output, after all.  Please use your judgement
        as to whether to translate this term or not, expanded or not.
        """,
        msg="""
        Decrypt bucket item session keys:

          \b
          MAC key (master key): {sign_key}
          Authenticated content: {ciphertext}
          Claimed MAC value: {claimed_mac}
          Computed MAC value: {actual_mac}
        """,
        context='debug message',
        flags='python-brace-format',
    )
    DERIVED_MASTER_KEYS_KEYS = _prepare_translatable(
        msg="""
        Derived master keys' keys:

          \b
          Encryption key: {enc_key}
          Signing key: {sign_key}
          Password: {pw_bytes}
          Function call: pbkdf2(algorithm={algorithm!r}, length={length!r}, salt={salt!r}, iterations={iterations!r})

        """,  # noqa: E501
        comments='',
        context='debug message',
        flags='python-brace-format',
    )
    DIRECTORY_CONTENTS_CHECK_OK = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "storeroom"-type configuration directories, while
        "assembling" the items stored in the configuration according to
        the item's "path".  Each "directory" in the path contains a list
        of children it claims to contain, and this list must be matched
        against the actual discovered items.  Now, at the end, we
        actually confirm the claim.  (We would have already thrown an
        error here otherwise.)
        """,
        msg='Directory contents check OK: {path} -> {contents}',
        context='debug message',
        flags='python-brace-format',
    )
    MASTER_KEYS_DATA_MAC_INFO = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The MAC stands for "message authentication code",
        which guarantees the authenticity of the message to anyone who
        holds the corresponding key, similar to a digital signature.
        The acronym "MAC" is assumed to be well-known to the English
        target audience, or at least discoverable by them; they *are*
        asking for debug output, after all.  Please use your judgement
        as to whether to translate this term or not, expanded or not.
        """,
        msg="""
        Master keys data:

          \b
          MAC key: {sign_key}
          Authenticated content: {ciphertext}
          Claimed MAC value: {claimed_mac}
          Computed MAC value: {actual_mac}
        """,
        context='debug message',
        flags='python-brace-format',
    )
    POSTPONING_DIRECTORY_CONTENTS_CHECK = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "storeroom"-type configuration directories, while
        "assembling" the items stored in the configuration according to
        the item's "path".  Each "directory" in the path contains a list
        of children it claims to contain, and this list must be matched
        against the actual discovered items.  When emitting this
        message, we merely indicate that we saved the "claimed" list for
        this directory for later.
        """,
        msg='Postponing directory contents check: {path} -> {contents}',
        context='debug message',
        flags='python-brace-format',
    )
    SETTING_CONFIG_STRUCTURE_CONTENTS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "storeroom"-type configuration directories, while
        "assembling" the items stored in the configuration according to
        the item's "path".  We confirm that we set the entry at the
        given path to the given value.
        """,
        msg='Setting contents: {path} -> {value}',
        context='debug message',
        flags='python-brace-format',
    )
    SETTING_CONFIG_STRUCTURE_CONTENTS_EMPTY_DIRECTORY = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "storeroom"-type configuration directories, while
        "assembling" the items stored in the configuration according to
        the item's "path".  We confirm that we set up a currently empty
        directory at the given path.
        """,
        msg='Setting contents (empty directory): {path}',
        context='debug message',
        flags='python-brace-format',
    )
    VAULT_NATIVE_EVP_BYTESTOKEY_INIT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "native"-type configuration directories: in v0.2,
        the non-standard and deprecated "EVP_bytestokey" function from
        OpenSSL must be reimplemented from scratch.  The terms "salt"
        and "IV" (initialization vector) are cryptographic terms.
        """,
        msg="""
        evp_bytestokey_md5 (initialization):

          \b
          Input: {data}
          Salt: {salt}
          Key size: {key_size}
          IV size: {iv_size}
          Buffer length: {buffer_length}
          Buffer: {buffer}
        """,
        context='debug message',
        flags='python-brace-format',
    )
    VAULT_NATIVE_EVP_BYTESTOKEY_RESULT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "native"-type configuration directories: in v0.2,
        the non-standard and deprecated "EVP_bytestokey" function from
        OpenSSL must be reimplemented from scratch.  The terms "salt"
        and "IV" (initialization vector) are cryptographic terms.
        This function reports on the updated buffer length and contents
        after executing one round of hashing.
        """,
        msg="""
        evp_bytestokey_md5 (result):

          \b
          Encryption key: {enc_key}
          IV: {iv}
        """,
        context='debug message',
        flags='python-brace-format',
    )
    VAULT_NATIVE_EVP_BYTESTOKEY_ROUND = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "native"-type configuration directories: in v0.2,
        the non-standard and deprecated "EVP_bytestokey" function from
        OpenSSL must be reimplemented from scratch.  The terms "salt"
        and "IV" (initialization vector) are cryptographic terms.
        This function reports on the updated buffer length and contents
        after executing one round of hashing.
        """,
        msg="""
        evp_bytestokey_md5 (round update):

          \b
          Buffer length: {buffer_length}
          Buffer: {buffer}
        """,
        context='debug message',
        flags='python-brace-format',
    )
    VAULT_NATIVE_CHECKING_MAC_DETAILS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "native"-type configuration directories.  It is
        preceded by the info message PARSING_IV_PAYLOAD_MAC; see the
        commentary there concerning the terms and thoughts on
        translating them.
        """,
        msg="""
        MAC details:

          \b
          MAC input: {mac_input}
          Expected MAC: {mac}
        """,
        context='debug message',
        flags='python-brace-format',
    )
    VAULT_NATIVE_PADDED_PLAINTEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "native"-type configuration directories.  "padding"
        and "plaintext" are cryptographic terms.
        """,
        msg='Padded plaintext: {contents}',
        context='debug message',
        flags='python-brace-format',
    )
    VAULT_NATIVE_PARSE_BUFFER = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "native"-type configuration directories.  It is
        preceded by the info message PARSING_IV_PAYLOAD_MAC; see the
        commentary there concerning the terms and thoughts on
        translating them.
        """,
        msg="""
        Buffer: {contents}

          \b
          IV: {iv}
          Payload: {payload}
          MAC: {mac}
        """,
        context='debug message',
        flags='python-brace-format',
    )
    VAULT_NATIVE_PLAINTEXT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "native"-type configuration directories.
        "plaintext" is a cryptographic term.
        """,
        msg='Plaintext: {contents}',
        context='debug message',
        flags='python-brace-format',
    )
    VAULT_NATIVE_PBKDF2_CALL = _prepare_translatable(
        msg="""
        Master key derivation:

          \b
          PBKDF2 call: PBKDF2-HMAC(password={password!r}, salt={salt!r}, iterations={iterations!r}, key_size={key_size!r}, algorithm={algorithm!r})
          Result (binary): {raw_result}
          Result (hex key): {result_key!r}
        """,  # noqa: E501
        comments='',
        context='debug message',
        flags='python-brace-format',
    )
    VAULT_NATIVE_V02_PAYLOAD_MAC_POSTPROCESSING = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "native"-type configuration directories.  It is
        preceded by the info message PARSING_IV_PAYLOAD_MAC and the
        debug message PARSING_NATIVE_PARSE_BUFFER; see the commentary
        there concerning the terms and thoughts on translating them.
        """,
        msg="""
        Postprocessing buffer (v0.2):

          \b
          Payload: {payload} (decoded from base64)
          MAC: {mac} (decoded from hex)
        """,
        context='debug message',
        flags='python-brace-format',
    )


class InfoMsgTemplate(enum.Enum):
    ASSEMBLING_CONFIG_STRUCTURE = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "storeroom"-type configuration directories.  The
        system stores entries in different "buckets" of a hash table.
        After the respective items in the buckets have been decrypted,
        we then have a list of item paths plus contents to populate.
        This must be done in a certain order (we don't yet have an
        existing directory tree to rely on, but rather must build it
        on-the-fly), hence the term "assembling".
        """,
        msg='Assembling config structure',
        context='info message',
    )
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
    CHECKING_CONFIG_STRUCTURE_CONSISTENCY = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "storeroom"-type configuration directories.  Having
        "assembled" the configuration items according to their claimed
        paths and contents, we then check if the assembled structure is
        internally consistent.
        """,
        msg='Checking config structure consistency',
        context='info message',
    )
    DECRYPTING_BUCKET = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "storeroom"-type configuration directories.  The
        system stores entries in different "buckets" of a hash table.
        We parse the directory bucket by bucket.  All buckets are
        numbered in hexadecimal, and typically there are 32 buckets, so
        2-digit hex numbers.
        """,
        msg='Decrypting bucket {bucket_number}',
        context='info message',
        flags='python-brace-format',
    )
    PARSING_MASTER_KEYS_DATA = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "storeroom"-type configuration directories.
        `.keys` is a filename, from which data about the master keys for
        this configuration are loaded.
        """,
        msg='Parsing master keys data from .keys',
        context='info message',
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
    VAULT_NATIVE_CHECKING_MAC = _prepare_translatable(
        msg='Checking MAC',
        comments='',
        context='info message',
    )
    VAULT_NATIVE_DECRYPTING_CONTENTS = _prepare_translatable(
        msg='Decrypting contents',
        comments='',
        context='info message',
    )
    VAULT_NATIVE_DERIVING_KEYS = _prepare_translatable(
        msg='Deriving an encryption and signing key',
        comments='',
        context='info message',
    )
    VAULT_NATIVE_PARSING_IV_PAYLOAD_MAC = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This message is emitted by the vault configuration
        exporter for "native"-type configuration directories.  "IV"
        means "initialization vector", and "MAC" means "message
        authentication code".  They are specifically cryptographic
        terms, as is "payload".  The acronyms "IV" and "MAC" are assumed
        to be well-known to the English target audience, or at least
        discoverable by them; they *are* asking for debug output, after
        all.  Please use your judgement as to whether to translate this
        term or not, expanded or not.
        """,
        msg='Parsing IV, payload and MAC from the file contents',
        context='info message',
    )


class WarnMsgTemplate(enum.Enum):
    EMPTY_SERVICE_NOT_SUPPORTED = _prepare_translatable(
        comments='',
        msg="""
        An empty {service_metavar!s} is not supported by vault(1).
        For compatibility, this will be treated as if SERVICE was not
        supplied, i.e., it will error out, or operate on global settings.
        """,
        context='warning message',
        flags='python-brace-format',
    )
    EMPTY_SERVICE_SETTINGS_INACCESSIBLE = _prepare_translatable(
        msg="""
        An empty {service_metavar!s} is not supported by vault(1).
        The empty-string service settings will be inaccessible and
        ineffective.  To ensure that vault(1) and {PROG_NAME!s} see the
        settings, move them into the "global" section.
        """,
        comments='',
        context='warning message',
        flags='python-brace-format',
    )
    FAILED_TO_MIGRATE_CONFIG = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "error" is supplied by the operating system
        (errno/strerror).
        """,
        msg='Failed to migrate to {path!r}: {error!s}: {filename!r}.',
        context='warning message',
        flags='python-brace-format',
    )
    GLOBAL_PASSPHRASE_INEFFECTIVE = _prepare_translatable(
        msg=r"""
        Setting a global passphrase is ineffective
        because a key is also set.
        """,
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
        msg=r"""
        The {key!s} passphrase is not {form!s}-normalized.  Its
        serialization as a byte string may not be what you expect it to
        be, even if it *displays* correctly.  Please make sure to
        double-check any derived passphrases for unexpected results.
        """,
        context='warning message',
        flags='python-brace-format',
    )
    SERVICE_NAME_INCOMPLETABLE = _prepare_translatable(
        msg="""
        The service name {service!r} contains an ASCII control
        character, which is not supported by our shell completion code.
        This service name will therefore not be available for completion
        on the command-line.  You may of course still type it in
        manually in whatever format your shell accepts, but we highly
        recommend choosing a different service name instead.
        """,
        comments='',
        context='warning message',
        flags='python-brace-format',
    )
    SERVICE_PASSPHRASE_INEFFECTIVE = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The key that is set need not necessarily be set at
        the service level; it may be a global key as well.
        """,
        msg=r"""
        Setting a service passphrase is ineffective because a key is
        also set: {service!s}.
        """,
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
        msg=r"""
        Using deprecated v0.1-style config file {old!r}, instead of
        v0.2-style {new!r}.  Support for v0.1-style config filenames
        will be removed in v1.0.
        """,
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
        msg="""
        A subcommand will be required here in v1.0.  See --help for
        available subcommands.  Defaulting to subcommand "vault".
        """,
        context='deprecation warning message',
    )


class ErrMsgTemplate(enum.Enum):
    AGENT_REFUSED_LIST_KEYS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "loaded keys" being keys loaded into the agent.
        """,
        msg="""
        The SSH agent failed to or refused to supply a list of loaded keys.
        """,
        context='error message',
    )
    AGENT_REFUSED_SIGNATURE = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The message to be signed is the vault UUID, but
        there's no space to explain that here, so ideally the error
        message does not go into detail.
        """,
        msg="""
        The SSH agent failed to or refused to issue a signature with the
        selected key, necessary for deriving a service passphrase.
        """,
        context='error message',
    )
    CANNOT_CONNECT_TO_AGENT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "error" is supplied by the operating system
        (errno/strerror).
        """,
        msg='Cannot connect to the SSH agent: {error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_DECODEIMPORT_VAULT_SETTINGS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "error" is supplied by the operating system
        (errno/strerror).
        """,
        msg='Cannot import vault settings: cannot decode JSON: {error!s}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_EXPORT_VAULT_SETTINGS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "error" is supplied by the operating system
        (errno/strerror).
        """,
        msg='Cannot export vault settings: {error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_IMPORT_VAULT_SETTINGS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "error" is supplied by the operating system
        (errno/strerror).
        """,
        msg='Cannot import vault settings: {error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_LOAD_USER_CONFIG = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "error" is supplied by the operating system
        (errno/strerror).
        """,
        msg='Cannot load user config: {error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_LOAD_VAULT_SETTINGS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "error" is supplied by the operating system
        (errno/strerror).
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
        msg=r"""
        Cannot parse {path!r} as a valid vault-native configuration
        file/directory.
        """,
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_PARSE_AS_VAULT_CONFIG_OSERROR = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "error" is supplied by the operating system
        (errno/strerror).
        """,
        msg=r"""
        Cannot parse {path!r} as a valid vault-native configuration
        file/directory: {error!s}: {filename!r}.
        """,
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_STORE_VAULT_SETTINGS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "error" is supplied by the operating system
        (errno/strerror).
        """,
        msg='Cannot store vault settings: {error!s}: {filename!r}.',
        context='error message',
        flags='python-brace-format',
    )
    CANNOT_UNDERSTAND_AGENT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: This error message is used whenever we cannot make
        any sense of a response from the SSH agent because the response
        is ill-formed (truncated, improperly encoded, etc.) or otherwise
        violates the communications protocol.  Well-formed responses
        that adhere to the protocol, even if they indicate that the
        requested operation failed, are handled with a different error
        message.
        """,
        msg="""
        Cannot understand the SSH agent's response because it violates
        the communications protocol.
        """,
        context='error message',
    )
    CANNOT_UPDATE_SETTINGS_NO_SETTINGS = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The settings_type metavar contains translations for
        either "global settings" or "service-specific settings"; see the
        CANNOT_UPDATE_SETTINGS_METAVAR_SETTINGS_TYPE_GLOBAL and
        CANNOT_UPDATE_SETTINGS_METAVAR_SETTINGS_TYPE_SERVICE entries.
        The first sentence will thus read either "Cannot update the
        global settings without any given settings." or "Cannot update
        the service-specific settings without any given settings.".  You
        may update this entry, and the two metavar entries, in any way
        you see fit that achieves the desired translations of the first
        sentence.
        """,
        msg=r"""
        Cannot update the {settings_type!s} without any given settings.
        You must specify at least one of --lower, ..., --symbol, or
        --phrase or --key.
        """,
        context='error message',
        flags='python-brace-format',
    )
    INVALID_USER_CONFIG = _prepare_translatable(
        comments=r"""
        TRANSLATORS: "error" is supplied by the operating system
        (errno/strerror).
        """,
        msg=r"""
        The user configuration file is invalid.  {error!s}: {filename!r}.
        """,
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
        msg=r"""
        Cannot connect to an SSH agent because this Python version does
        not support UNIX domain sockets.
        """,
        comments='',
        context='error message',
    )
    NO_KEY_OR_PHRASE = _prepare_translatable(
        msg=r"""
        No passphrase or key was given in the configuration.  In this
        case, the --phrase or --key argument is required.
        """,
        comments='',
        context='error message',
    )
    NO_SSH_AGENT_FOUND = _prepare_translatable(
        'Cannot find any running SSH agent because SSH_AUTH_SOCK is not set.',
        comments='',
        context='error message',
    )
    NO_SUITABLE_SSH_KEYS = _prepare_translatable(
        msg="""
        The SSH agent contains no keys suitable for {PROG_NAME!s}.
        """,  # noqa: RUF027
        comments='',
        context='error message',
        flags='python-brace-format',
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
        the metavar is Label.VAULT_METAVAR_SERVICE.
        """,
        msg='{param!s} requires a {service_metavar!s} or --config.',
        context='error message',
        flags='python-brace-format',
    )
    PARAMS_NEEDS_SERVICE = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The param is a long-form command-line option name,
        the metavar is Label.VAULT_METAVAR_SERVICE.
        """,
        msg='{param!s} requires a {service_metavar!s}.',
        context='error message',
        flags='python-brace-format',
    )
    PARAMS_NO_SERVICE = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The param is a long-form command-line option name,
        the metavar is Label.VAULT_METAVAR_SERVICE.
        """,
        msg='{param!s} does not take a {service_metavar!s} argument.',
        context='error message',
        flags='python-brace-format',
    )
    SERVICE_REQUIRED = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The metavar is Label.VAULT_METAVAR_SERVICE.
        """,
        msg='Deriving a passphrase requires a {service_metavar!s}.',
        context='error message',
        flags='python-brace-format',
    )
    SET_AND_UNSET_SAME_SETTING = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The rephrasing "Attempted to unset and set the same
        setting (--unset={setting!s} --{setting!s}=...) at the same
        time." may or may not be more suitable as a basis for
        translation instead.
        """,
        msg='Attempted to unset and set --{setting!s} at the same time.',
        context='error message',
        flags='python-brace-format',
    )
    SSH_KEY_NOT_LOADED = _prepare_translatable(
        'The requested SSH key is not loaded into the agent.',
        comments='',
        context='error message',
    )
    USER_ABORTED_EDIT = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The user requested to edit the notes for a service,
        but aborted the request mid-editing.
        """,
        msg='Not saving any new notes: the user aborted the request.',
        context='error message',
    )
    USER_ABORTED_PASSPHRASE = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The user was prompted for a master passphrase,
        but aborted the request.
        """,
        msg='No passphrase was given; the user aborted the request.',
        context='error message',
    )
    USER_ABORTED_SSH_KEY_SELECTION = _prepare_translatable(
        comments=r"""
        TRANSLATORS: The user was prompted to select a master SSH key,
        but aborted the request.
        """,
        msg='No SSH key was selected; the user aborted the request.',
        context='error message',
    )


MsgTemplate: TypeAlias = Union[
    Label,
    DebugMsgTemplate,
    InfoMsgTemplate,
    WarnMsgTemplate,
    ErrMsgTemplate,
]
MSG_TEMPLATE_CLASSES = (
    Label,
    DebugMsgTemplate,
    InfoMsgTemplate,
    WarnMsgTemplate,
    ErrMsgTemplate,
)

DebugTranslations._load_cache()  # noqa: SLF001



def _write_po_file(  # noqa: C901
    fileobj: TextIO,
    /,
    *,
    is_template: bool = True,
    version: str = __version__,
) -> None:  # pragma: no cover
    r"""Write a .po file to the given file object.

    Assumes the file object is opened for writing and accepts string
    inputs.  The file will *not* be closed when writing is complete.
    The file *must* be opened in UTF-8 encoding, lest the file will
    declare an incorrect encoding.

    This function crucially depends on all translatable strings
    appearing in the enums of this module.  Certain parts of the
    .po header are hard-coded, as is the source filename.

    """  # noqa: DOC501
    entries: dict[str, dict[str, MsgTemplate]] = {}
    for enum_class in MSG_TEMPLATE_CLASSES:
        for member in enum_class.__members__.values():
            value = cast('TranslatableString', member.value)
            ctx = value.l10n_context
            msg = value.singular
            if (
                msg in entries.setdefault(ctx, {})
                and entries[ctx][msg] != member
            ):
                raise AssertionError(  # noqa: TRY003
                    f'Duplicate entry for ({ctx!r}, {msg!r}): '  # noqa: EM102
                    f'{entries[ctx][msg]!r} and {member!r}'
                )
            entries[ctx][msg] = member
    build_time = datetime.datetime.now().astimezone()
    if is_template:
        header = (
            inspect.cleandoc(rf"""
            # English translation for {PROG_NAME!s}.
            # Copyright (C) {build_time.strftime('%Y')} AUTHOR
            # This file is distributed under the same license as {PROG_NAME!s}.
            # AUTHOR <someone@example.com>, {build_time.strftime('%Y')}.
            #
            msgid ""
            msgstr ""
            """).removesuffix('\n')
            + '\n'
        )
    else:
        header = (
            inspect.cleandoc(rf"""
            # English debug translation for {PROG_NAME!s}.
            # Copyright (C) {build_time.strftime('%Y')} {__author__}
            # This file is distributed under the same license as {PROG_NAME!s}.
            #
            msgid ""
            msgstr ""
            """).removesuffix('\n')
            + '\n'
        )
    fileobj.write(header)
    po_info = {
        'Project-Id-Version': f'{PROG_NAME} {version}',
        'Report-Msgid-Bugs-To': 'software@the13thletter.info',
        'PO-Revision-Date': build_time.strftime('%Y-%m-%d %H:%M%z'),
        'MIME-Version': '1.0',
        'Content-Type': 'text/plain; charset=UTF-8',
        'Content-Transfer-Encoding': '8bit',
        'Plural-Forms': 'nplurals=2; plural=(n != 1);',
    }
    if is_template:
        po_info.update({
            'POT-Creation-Date': build_time.strftime('%Y-%m-%d %H:%M%z'),
            'Last-Translator': 'AUTHOR <someone@example.com>',
            'Language': 'en',
            'Language-Team': 'English',
        })
    else:
        po_info.update({
            'Last-Translator': __author__,
            'Language': 'en_DEBUG',
            'Language-Team': 'English',
        })
    print(*_format_po_info(po_info), sep='\n', end='\n', file=fileobj)
    for _ctx, subdict in sorted(entries.items()):
        for _msg, enum_value in sorted(
            subdict.items(),
            key=lambda kv: str(kv[1]),
        ):
            value = cast('TranslatableString', enum_value.value)
            value2 = value.maybe_without_filename()
            fileobj.writelines(
                _format_po_entry(
                    enum_value, is_debug_translation=not is_template
                )
            )
            if value != value2:
                fileobj.writelines(
                    _format_po_entry(
                        enum_value,
                        is_debug_translation=not is_template,
                        transformed_string=value2,
                    )
                )


def _format_po_info(
    data: Mapping[str, Any],
    /,
) -> Iterator[str]:  # pragma: no cover
    sortorder = [
        'project-id-version',
        'report-msgid-bugs-to',
        'pot-creation-date',
        'po-revision-date',
        'last-translator',
        'language',
        'language-team',
        'mime-version',
        'content-type',
        'content-transfer-encoding',
        'plural-forms',
    ]

    def _sort_position(s: str, /) -> int:
        n = len(sortorder)
        for i, x in enumerate(sortorder):
            if s.lower().rstrip(':') == x:
                return i
        return n

    for key in sorted(data.keys(), key=_sort_position):
        value = data[key]
        line = f"{key}: {value}\n"
        yield _cstr(line)


def _format_po_entry(
    enum_value: MsgTemplate,
    /,
    *,
    is_debug_translation: bool = False,
    transformed_string: TranslatableString | None = None,
) -> tuple[str, ...]:  # pragma: no cover
    ret: list[str] = ['\n']
    ts = transformed_string or cast('TranslatableString', enum_value.value)
    if ts.translator_comments:
        comments = ts.translator_comments.splitlines(False)  # noqa: FBT003
        comments.extend(['', f'Message-ID: {enum_value}'])
    else:
        comments = [f'TRANSLATORS: Message-ID: {enum_value}']
    ret.extend(f'#. {line}\n' for line in comments)
    if ts.flags:
        ret.append(f'#, {", ".join(sorted(ts.flags))}\n')
    if ts.l10n_context:
        ret.append(f'msgctxt {_cstr(ts.l10n_context)}\n')
    ret.append(f'msgid {_cstr(ts.singular)}\n')
    if ts.plural:
        ret.append(f'msgid_plural {_cstr(ts.plural)}\n')
    value = (
        DebugTranslations().pgettext(ts.l10n_context, ts.singular)
        if is_debug_translation
        else ''
    )
    ret.append(f'msgstr {_cstr(value)}\n')
    return tuple(ret)


def _cstr(s: str) -> str:  # pragma: no cover
    def escape(string: str) -> str:
        return string.translate({
            0: r'\000',
            1: r'\001',
            2: r'\002',
            3: r'\003',
            4: r'\004',
            5: r'\005',
            6: r'\006',
            7: r'\007',
            8: r'\b',
            9: r'\t',
            10: r'\n',
            11: r'\013',
            12: r'\f',
            13: r'\r',
            14: r'\016',
            15: r'\017',
            ord('"'): r'\"',
            ord('\\'): r'\\',
            127: r'\177',
        })

    return '\n'.join(
        f'"{escape(line)}"'
        for line in s.splitlines(True) or ['']  # noqa: FBT003
    )


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ex = ap.add_mutually_exclusive_group()
    ex.add_argument(
        '--template',
        action='store_true',
        dest='is_template',
        default=True,
        help='Generate a template file (default)',
    )
    ex.add_argument(
        '--debug-translation',
        action='store_false',
        dest='is_template',
        default=True,
        help='Generate a "debug" translation file',
    )
    ap.add_argument(
        '--set-version',
        action='store',
        dest='version',
        default=__version__,
        help='Override declared software version',
    )
    args = ap.parse_args()
    _write_po_file(
        sys.stdout,
        version=args.version,
        is_template=args.is_template,
    )
