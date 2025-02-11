# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-Licence-Identifier: MIT

"""Messages for the command-line interface of `derivepassphrase`.

Also contains some machinery related to internationalization and
localization.

!!! warning

    Non-public module (implementation detail), provided for didactical and
    educational purposes only.  Subject to change without notice, including
    removal.

"""

from __future__ import annotations

import contextlib
import datetime
import enum
import functools
import gettext
import inspect
import os
import pathlib
import string
import sys
import textwrap
import types
from typing import TYPE_CHECKING, NamedTuple, Protocol, TextIO, Union, cast

from typing_extensions import TypeAlias, override

from derivepassphrase import _internals

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping, Sequence

    from typing_extensions import Any, Self

__all__ = ('PROG_NAME',)

PROG_NAME = _internals.PROG_NAME
VERSION = _internals.VERSION
AUTHOR = _internals.AUTHOR


def load_translations(
    localedirs: list[str | bytes | os.PathLike] | None = None,
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

    Raises:
        RuntimeError:
            `APPDATA` (on Windows) or `XDG_DATA_HOME` (otherwise) is not
            set.  We attempted to compute the default value, but failed
            to determine the home directory.

    """
    if localedirs is None:
        # TODO(the-13th-letter): Define a public (and opaque) enum for these
        # special directories so that they are available to callers as well,
        # without computation.  Shift the computation into a separate
        # top-level function, so that it can be stubbed during tests.
        # Support the `.../site-packages/share/locale` special directory via
        # a new enum value, because that is where the derivepassphrase wheel
        # stores its packaged translations.  Then reimplement `gettext.find`
        # and `gettext.translation` with support for `importlib.resources`.
        # The heavy lifting is already being done by `locale.normalize`.
        if sys.platform.startswith('win'):
            xdg_data_home = (
                pathlib.Path(os.environ['APPDATA'])
                if os.environ.get('APPDATA')
                else pathlib.Path('~').expanduser()
            )
        elif os.environ.get('XDG_DATA_HOME'):
            xdg_data_home = pathlib.Path(os.environ['XDG_DATA_HOME'])
        else:
            xdg_data_home = (
                pathlib.Path('~').expanduser() / '.local' / '.share'
            )
        localedirs = [
            pathlib.Path(xdg_data_home, 'locale'),
            pathlib.Path(sys.prefix, 'share', 'locale'),
            pathlib.Path(sys.base_prefix, 'share', 'locale'),
        ]
    for localedir in localedirs:
        with contextlib.suppress(OSError):
            return gettext.translation(
                PROG_NAME,
                localedir=os.fsdecode(localedir),
                languages=languages,
                class_=class_,
            )
    return gettext.NullTranslations()


translation = load_translations()
_debug_translation_message_cache: dict[
    tuple[str, str],
    tuple[MsgTemplate, frozenset],
] = {}


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
                queue: list[tuple[TranslatableString, frozenset[str]]] = [
                    (value, frozenset())
                ]
                value2 = value.maybe_without_filename()
                if value != value2:
                    queue.append((value2, frozenset({'filename'})))
                for v, trimmed in queue:
                    singular = v.singular
                    plural = v.plural
                    context = v.l10n_context
                    cache.setdefault((context, singular), (member, trimmed))
                    # Currently no translatable messages use plural forms
                    if plural:  # pragma: no cover
                        cache.setdefault((context, plural), (member, trimmed))

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
            enum_value, trimmed = _debug_translation_message_cache[
                context, message
            ]
        except KeyError:
            return message if not message_plural or n == 1 else message_plural
        return cls._format_enum_name_maybe_with_fields(
            enum_name=str(enum_value),
            ts=cast('TranslatableString', enum_value.value),
            trimmed=trimmed,
        )

    @staticmethod
    def _format_enum_name_maybe_with_fields(
        enum_name: str,
        ts: TranslatableString,
        trimmed: frozenset[str] = frozenset(),
    ) -> str:
        formatted_fields = [
            f'{f}=None' if f in trimmed else f'{f}={{{f}!r}}'
            for f in ts.fields()
        ]
        return (
            '{}({})'.format(enum_name, ', '.join(formatted_fields))
            if formatted_fields
            else str(enum_name)
        )

    @override
    def gettext(
        self,
        message: str,
        /,
    ) -> str:
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
    """Translatable string as used by the `derivepassphrase` command-line.

    For typing purposes.

    Attributes:
        l10n_context:
            The localization context, as per [`gettext`][].  Used to
            disambiguate different uses of the same translatable string.
        singular:
            The translatable message, base case.
        plural:
            The translatable message, plural case.  Usually unset.
        translator_comments:
            Explicit commentary for the translator.
        flags:
            `.mo` file flags for this message, e.g. to indicate the
            string formatting style in use.

    """

    l10n_context: str
    """"""
    singular: str
    """"""
    plural: str = ''
    """"""
    flags: frozenset[str] = frozenset()
    """"""
    translator_comments: str = ''
    """"""

    def fields(self) -> list[str]:
        """Return the replacement fields this template requires.

        Raises:
            NotImplementedError:
                Replacement field discovery for %-formatting is not
                implemented.

        """
        if 'python-format' in self.flags:  # pragma: no cover
            err_msg = (
                'Replacement field discovery for %-formatting '
                'is not implemented'
            )
            raise NotImplementedError(err_msg)
        if (
            'no-python-brace-format' in self.flags
            or 'python-brace-format' not in self.flags
        ):
            return []
        formatter = string.Formatter()
        fields: dict[str, int] = {}
        for _lit, field, _spec, _conv in formatter.parse(self.singular):
            if field is not None and field not in fields:
                fields[field] = len(fields)
        return sorted(fields, key=fields.__getitem__)

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
        `"Cannot open file: {error}: {filename!r}."`, but not
        necessarily in other languages.

        """
        filename_str = ': {filename!r}'
        ret = self
        a, sep1, b = self.singular.partition(filename_str)
        c, sep2, d = self.plural.partition(filename_str)
        if sep1:
            ret = ret._replace(singular=(a + b))
        # Currently no translatable messages use plural forms
        if sep2:  # pragma: no cover
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
        if comments.strip() and not comments.lstrip().startswith(
            'TRANSLATORS:'
        ):  # pragma: no cover
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

        Examples:
            >>> TranslatableString('', 'all OK').validate_flags()
            ... # doctest: +NORMALIZE_WHITESPACE
            TranslatableString(l10n_context='', singular='all OK', plural='',
                               flags=frozenset(), translator_comments='')
            >>> TranslatableString('', '20% OK').validate_flags(
            ...     'no-python-format'
            ... )
            ... # doctest: +NORMALIZE_WHITESPACE
            TranslatableString(l10n_context='', singular='20% OK', plural='',
                               flags=frozenset({'no-python-format'}),
                               translator_comments='')
            >>> TranslatableString('', '%d items').validate_flags()
            ... # doctest: +ELLIPSIS
            Traceback (most recent call last):
                ...
            ValueError: Missing flag for how to deal with percent character ...
            >>> TranslatableString('', '{braces}').validate_flags()
            ... # doctest: +ELLIPSIS
            Traceback (most recent call last):
                ...
            ValueError: Missing flag for how to deal with brace character ...
            >>> TranslatableString('', 'no braces').validate_flags(
            ...     'python-brace-format'
            ... )
            ... # doctest: +ELLIPSIS
            Traceback (most recent call last):
                ...
            ValueError: Missing format string parameters ...

        """
        all_flags = frozenset(f.strip() for f in self.flags.union(extra_flags))
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
    definitions more readable.  It is the main implementation of the
    [`TranslatableStringConstructor`][].

    """
    flags = (
        frozenset(flags) if not isinstance(flags, str) else frozenset({flags})
    )
    return (
        TranslatableString(context, single, plural=plural, flags=flags)
        .rewrapped()
        .with_comments(comments)
        .validate_flags()
    )


class TranslatedString:
    """A string object that stringifies to its translation.

    The translation and replacement value rendering is only performed
    when this string object is actually stringified.

    """

    def __init__(
        self,
        template: str | TranslatableString | MsgTemplate,
        args_dict: Mapping[str, Any] = types.MappingProxyType({}),
        /,
        **kwargs: Any,  # noqa: ANN401
    ) -> None:
        """Initializer.

        Args:
            template:
                A template string, suitable for [`str.format`][].  If
                a string, use it directly.  If
                a [`TranslatableString`][], or a known enum value whose
                value is a `TranslatableString`, then use that string's
                "singular" entry.
            args_dict:
                Keyword arguments to be passed to [`str.format`][].
            kwargs:
                More keyword arguments to be passed to [`str.format`][].

        """
        if isinstance(template, MSG_TEMPLATE_CLASSES):
            template = cast('TranslatableString', template.value)
        self.template = template
        self.kwargs = {**args_dict, **kwargs}
        self._rendered: str | None = None

    def __bool__(self) -> bool:
        """Return true if the rendered string is truthy."""
        return bool(str(self))

    def __eq__(self, other: object) -> bool:  # pragma: no cover
        """Return true if the rendered string is equal to `other`."""
        return str(self) == other

    def __hash__(self) -> int:  # pragma: no cover
        """Return the hash of the rendered string."""
        return hash(str(self))

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f'{self.__class__.__name__}({self.template!r}, '
            f'{dict(self.kwargs)!r})'
        )

    def __str__(self) -> str:
        """Return the rendered translation of this string.

        First, look up the translation of the string's template.  Then
        fill in the replacement fields.  Cache the result for future
        calls.

        """
        if self._rendered is None:
            do_escape = False
            if isinstance(self.template, str):
                context = ''
                template = self.template
            else:
                context = self.template.l10n_context
                template = self.template.singular
                do_escape = 'no-python-brace-format' in self.template.flags
            template = (
                translation.pgettext(context, template)
                if context
                else translation.gettext(template)
            )
            template = self._escape(template) if do_escape else template
            kwargs = {
                k: str(v) if isinstance(v, TranslatedString) else v
                for k, v in self.kwargs.items()
            }
            self._rendered = template.format(**kwargs)
        return self._rendered

    @staticmethod
    def _escape(template: str) -> str:
        return template.translate({
            ord('{'): '{{',
            ord('}'): '}}',
        })

    @classmethod
    def constant(cls, template: str) -> Self:
        return cls(cls._escape(template))

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


class TranslatableStringConstructor(Protocol):
    """Construct a [`TranslatableString`][]."""

    def __call__(
        self,
        context: str,
        single: str,
        /,
        flags: Iterable[str] = (),
        plural: str = '',
        comments: str = '',
    ) -> TranslatableString:
        """Return a [`TranslatableString`][] from these parts.

        Usually some form of validation or normalization is performed
        first on these parts.

        The main implementation of this is in [`translatable`][].

        """


def commented(comments: str = '', /) -> TranslatableStringConstructor:
    """A "decorator" for readably constructing commented enum values.

    Returns a partial application of [`translatable`][] with the `comments`
    argument pre-filled.

    This is geared towards the quirks of the API documentation extractor
    `mkdocstrings-python`/`griffe`, which reformat and trim enum value
    declarations in predictable but somewhat weird ways.  Chains of function
    calls are preserved, though, so use this to our advantage to suggest
    a specific formatting.

    This is not necessarily good code style, nor is it a lightweight
    solution.

    """  # noqa: DOC201
    return functools.partial(translatable, comments=comments)


class Label(enum.Enum):
    """Labels for the `derivepassphrase` command-line.

    Includes help text (long-form and short-form), help metavar names,
    diagnostic labels and interactive prompts.

    """

    DEPRECATION_WARNING_LABEL = commented(
        'This is a short label that will be prepended to '
        'a warning message, e.g., "Deprecation warning: A subcommand '
        'will be required in v1.0."',
    )(
        'Label :: Diagnostics :: Marker',
        'Deprecation warning',
    )
    """"""
    WARNING_LABEL = commented(
        'This is a short label that will be prepended to '
        'a warning message, e.g., "Warning: An empty service name '
        'is not supported by vault(1)."',
    )(
        'Label :: Diagnostics :: Marker',
        'Warning',
    )
    """"""
    CANNOT_UPDATE_SETTINGS_METAVAR_SETTINGS_TYPE_GLOBAL = commented(
        'This is one of two values of the settings_type metavar '
        'used in the CANNOT_UPDATE_SETTINGS_NO_SETTINGS entry.  '
        'It is only used there.  '
        'The full sentence then reads: '
        '"Cannot update the global settings without any given settings."',
    )(
        'Label :: Error message :: Metavar',
        'global settings',
    )
    """"""
    CANNOT_UPDATE_SETTINGS_METAVAR_SETTINGS_TYPE_SERVICE = commented(
        'This is one of two values of the settings_type metavar '
        'used in the CANNOT_UPDATE_SETTINGS_NO_SETTINGS entry.  '
        'It is only used there.  '
        'The full sentence then reads: '
        '"Cannot update the service-specific settings without any '
        'given settings."',
    )(
        'Label :: Error message :: Metavar',
        'service-specific settings',
    )
    """"""
    CONFIGURATION_EPILOG = commented(
        '',
    )(
        'Label :: Help text :: Explanation',
        'Use $VISUAL or $EDITOR to configure the spawned editor.',
    )
    """"""
    DERIVEPASSPHRASE_02 = commented(
        '',
    )(
        'Label :: Help text :: Explanation',
        'The currently implemented subcommands are "vault" '
        '(for the scheme used by vault) and "export" '
        '(for exporting foreign configuration data).  '
        'See the respective `--help` output for instructions.  '
        'If no subcommand is given, we default to "vault".',
    )
    """"""
    DERIVEPASSPHRASE_03 = commented(
        '',
    )(
        'Label :: Help text :: Explanation',
        'Deprecation notice: Defaulting to "vault" is deprecated.  '
        'Starting in v1.0, the subcommand must be specified explicitly.',
    )
    """"""
    DERIVEPASSPHRASE_EPILOG_01 = commented(
        '',
    )(
        'Label :: Help text :: Explanation',
        'Configuration is stored in a directory according to the '
        '`DERIVEPASSPHRASE_PATH` variable, which defaults to '
        '`~/.derivepassphrase` on UNIX-like systems and '
        r'`C:\Users\<user>\AppData\Roaming\Derivepassphrase` on Windows.',
    )
    """"""
    DERIVEPASSPHRASE_EXPORT_02 = commented(
        '',
    )(
        'Label :: Help text :: Explanation',
        'The only available subcommand is "vault", '
        'which implements the vault-native configuration scheme.  '
        'If no subcommand is given, we default to "vault".',
    )
    """"""
    DERIVEPASSPHRASE_EXPORT_03 = DERIVEPASSPHRASE_03
    """"""
    DERIVEPASSPHRASE_EXPORT_VAULT_02 = commented(
        'The metavar is Label.EXPORT_VAULT_METAVAR_PATH.',
    )(
        'Label :: Help text :: Explanation',
        'Depending on the configuration format, '
        '{path_metavar} may either be a file or a directory.  '
        'We support the vault "v0.2", "v0.3" and "storeroom" formats.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_EXPORT_VAULT_03 = commented(
        'The metavar is Label.EXPORT_VAULT_METAVAR_PATH.',
    )(
        'Label :: Help text :: Explanation',
        'If {path_metavar} is explicitly given as `VAULT_PATH`, '
        'then use the `VAULT_PATH` environment variable to '
        'determine the correct path.  '
        '(Use `./VAULT_PATH` or similar to indicate a file/directory '
        'actually named `VAULT_PATH`.)',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_02 = commented(
        'The metavar is Label.VAULT_METAVAR_SERVICE.',
    )(
        'Label :: Help text :: Explanation',
        'If operating on global settings, or importing/exporting settings, '
        'then {service_metavar} must be omitted.  '
        'Otherwise it is required.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_EPILOG_01 = commented(
        '',
    )(
        'Label :: Help text :: Explanation',
        'WARNING: There is NO WAY to retrieve the generated passphrases '
        'if the master passphrase, the SSH key, or the exact '
        'passphrase settings are lost, '
        'short of trying out all possible combinations.  '
        'You are STRONGLY advised to keep independent backups of '
        'the settings and the SSH key, if any.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_EPILOG_02 = commented(
        '',
    )(
        'Label :: Help text :: Explanation',
        'The configuration is NOT encrypted, and you are '
        'STRONGLY discouraged from using a stored passphrase.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_NOTES_INSTRUCTION_TEXT = commented(
        "This instruction text is shown above the user's old stored notes "
        'for this service, if any, if the recommended '
        '"modern" editor interface is used.  '
        'The next line is the cut marking defined in '
        'Label.DERIVEPASSPHRASE_VAULT_NOTES_MARKER.'
    )(
        'Label :: Help text :: Explanation',
        """\
\b
# Enter notes below the line with the cut mark (ASCII scissors and
# dashes).  Lines above the cut mark (such as this one) will be ignored.
#
# If you wish to clear the notes, leave everything beyond the cut mark
# blank.  However, if you leave the *entire* file blank, also removing
# the cut mark, then the edit is aborted, and the old notes contents are
# retained.
#
""",
    )
    """"""
    DERIVEPASSPHRASE_VAULT_NOTES_LEGACY_INSTRUCTION_TEXT = commented(
        'This instruction text is shown if the vault(1)-compatible '
        '"legacy" editor interface is used and no previous notes exist.  '
        'The interface does not support commentary in the notes, '
        'so we fill this with obvious placeholder text instead.  '
        '(Please replace this with what *your* language/culture would '
        'obviously recognize as placeholder text.)'
    )(
        'Label :: Help text :: Explanation',
        'Lorem ipsum dolor sit amet, consectetur adipiscing elit, '
        'sed do eiusmod tempor incididunt ut labore '
        'et dolore magna aliqua.',
    )
    """"""
    PASSPHRASE_GENERATION_EPILOG = commented(
        'The metavar is Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.',
    )(
        'Label :: Help text :: Explanation',
        'Use {metavar}=0 to exclude a character type from the output.',
        flags='python-brace-format',
    )
    """"""
    STORAGE_MANAGEMENT_EPILOG = commented(
        'The metavar is Label.STORAGE_MANAGEMENT_METAVAR_PATH.',
    )(
        'Label :: Help text :: Explanation',
        'Using "-" as {metavar} for standard input/standard output '
        'is supported.',
        flags='python-brace-format',
    )
    """"""
    DEPRECATED_COMMAND_LABEL = commented(
        'We use this format string to indicate, at the beginning '
        "of a command's help text, that this command is deprecated.",
    )(
        'Label :: Help text :: Marker',
        '(Deprecated) {text}',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_NOTES_MARKER = commented(
        'The marker for separating the text from '
        'Label.DERIVEPASSPHRASE_VAULT_NOTES_INSTRUCTION_TEXT '
        "from the user's input (below the marker).  "
        'The first line starting with this label marks the separation point.',
    )(
        'Label :: Help text :: Marker',
        '# - - - - - >8 - - - - - >8 - - - - - >8 - - - - - >8 - - - - -',
    )
    """"""
    EXPORT_VAULT_FORMAT_METAVAR_FMT = commented(
        'This text is used as {metavar} in '
        'Label.EXPORT_VAULT_FORMAT_HELP_TEXT, yielding e.g. '
        '"Try the following storage format FMT."',
    )(
        'Label :: Help text :: Metavar :: export vault',
        'FMT',
    )
    """"""
    EXPORT_VAULT_KEY_METAVAR_K = commented(
        'This text is used as {metavar} in '
        'Label.EXPORT_VAULT_KEY_HELP_TEXT, yielding e.g. '
        '"Use K as the storage master key."',
    )(
        'Label :: Help text :: Metavar :: export vault',
        'K',
    )
    """"""
    EXPORT_VAULT_METAVAR_PATH = commented(
        'Used as "path_metavar" in '
        'Label.DERIVEPASSPHRASE_EXPORT_VAULT_02 and others, '
        'yielding e.g. "Depending on the configuration format, '
        'PATH may either be a file or a directory."',
    )(
        'Label :: Help text :: Metavar :: export vault',
        'PATH',
    )
    """"""
    PASSPHRASE_GENERATION_METAVAR_NUMBER = commented(
        'This metavar is used in Label.PASSPHRASE_GENERATION_EPILOG, '
        'Label.DERIVEPASSPHRASE_VAULT_LENGTH_HELP_TEXT and others, '
        'yielding e.g. "Ensure a passphrase length of NUMBER characters.".  ',
    )(
        'Label :: Help text :: Metavar :: vault',
        'NUMBER',
    )
    """"""
    STORAGE_MANAGEMENT_METAVAR_PATH = commented(
        'This metavar is used in Label.STORAGE_MANAGEMENT_EPILOG, '
        'Label.DERIVEPASSPHRASE_VAULT_IMPORT_HELP_TEXT and others, '
        'yielding e.g. "Ensure a passphrase length of NUMBER characters.".  ',
    )(
        'Label :: Help text :: Metavar :: vault',
        'PATH',
    )
    """"""
    VAULT_METAVAR_SERVICE = commented(
        'This metavar is used as "service_metavar" in multiple help texts, '
        'such as Label.DERIVEPASSPHRASE_VAULT_CONFIG_HELP_TEXT, '
        'Label.DERIVEPASSPHRASE_VAULT_02, ErrMsgTemplate.SERVICE_REQUIRED, '
        'etc.  Sample texts are "Deriving a passphrase requires a SERVICE.", '
        '"save the given settings for SERVICE, or global" and '
        '"If operating on global settings, or importing/exporting settings, '
        'then SERVICE must be omitted."',
    )(
        'Label :: Help text :: Metavar :: vault',
        'SERVICE',
    )
    """"""
    DEBUG_OPTION_HELP_TEXT = commented(
        '',
    )(
        'Label :: Help text :: One-line description',
        'Also emit debug information.  Implies --verbose.',
    )
    """"""
    DERIVEPASSPHRASE_01 = commented(
        'This is the first paragraph of the command help text, '
        'but it also appears (in truncated form, if necessary) '
        'as one-line help text for this command.  '
        'The translation should thus be as meaningful as possible '
        'even if truncated.',
    )(
        'Label :: Help text :: One-line description',
        'Derive a strong passphrase, deterministically, from a master secret.',
    )
    """"""
    DERIVEPASSPHRASE_EXPORT_01 = commented(
        'This is the first paragraph of the command help text, '
        'but it also appears (in truncated form, if necessary) '
        'as one-line help text for this command.  '
        'The translation should thus be as meaningful as possible '
        'even if truncated.',
    )(
        'Label :: Help text :: One-line description',
        'Export a foreign configuration to standard output.',
    )
    """"""
    DERIVEPASSPHRASE_EXPORT_VAULT_01 = commented(
        'This is the first paragraph of the command help text, '
        'but it also appears (in truncated form, if necessary) '
        'as one-line help text for this command.  '
        'The translation should thus be as meaningful as possible '
        'even if truncated.',
    )(
        'Label :: Help text :: One-line description',
        'Export a vault-native configuration to standard output.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_01 = commented(
        'This is the first paragraph of the command help text, '
        'but it also appears (in truncated form, if necessary) '
        'as one-line help text for this command.  '
        'The translation should thus be as meaningful as possible '
        'even if truncated.',
    )(
        'Label :: Help text :: One-line description',
        'Derive a passphrase using the vault derivation scheme.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_CONFIG_HELP_TEXT = commented(
        'The metavar is Label.VAULT_METAVAR_SERVICE.',
    )(
        'Label :: Help text :: One-line description',
        'Save the given settings for {service_metavar}, or global.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_DASH_HELP_TEXT = commented(
        'The metavar is Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.',
    )(
        'Label :: Help text :: One-line description',
        'Ensure at least {metavar} "-" or "_" characters.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_DELETE_ALL_HELP_TEXT = commented(
        '',
    )(
        'Label :: Help text :: One-line description',
        'Delete all settings.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_DELETE_GLOBALS_HELP_TEXT = commented(
        '',
    )(
        'Label :: Help text :: One-line description',
        'Delete the global settings.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_DELETE_HELP_TEXT = commented(
        'The metavar is Label.VAULT_METAVAR_SERVICE.',
    )(
        'Label :: Help text :: One-line description',
        'Delete the settings for {service_metavar}.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_EDITOR_INTERFACE_HELP_TEXT = commented(
        'The corresponding option is displayed as '
        '"--modern-editor-interface / --vault-legacy-editor-interface", '
        'so you may want to hint that the default (legacy) '
        'is the second of those options.  '
        'Though the vault(1) legacy editor interface clearly has deficiencies '
        'and (in my opinion) should only be used for compatibility purposes, '
        'the one-line help text should try not to sound too judgmental, '
        'if possible.',
    )(
        'Label :: Help text :: One-line description',
        'Edit notes using the modern editor interface '
        'or the vault-like legacy one (default).',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_EXPORT_AS_HELP_TEXT = commented(
        'The corresponding option is displayed as '
        '"--export-as=json|sh", so json refers to the JSON format (default) '
        'and sh refers to the POSIX sh format.  '
        'Please ensure that it is clear what the "json" and "sh" refer to '
        'in your translation... even if you cannot use texutal correspondence '
        'like the English text does.',
    )(
        'Label :: Help text :: One-line description',
        'When exporting, export as JSON (default) or as POSIX sh.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_EXPORT_HELP_TEXT = commented(
        'The metavar is Label.STORAGE_MANAGEMENT_METAVAR_PATH.',
    )(
        'Label :: Help text :: One-line description',
        'Export all saved settings to {metavar}.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_IMPORT_HELP_TEXT = commented(
        'The metavar is Label.STORAGE_MANAGEMENT_METAVAR_PATH.',
    )(
        'Label :: Help text :: One-line description',
        'Import saved settings from {metavar}.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_KEY_HELP_TEXT = commented(
        '',
    )(
        'Label :: Help text :: One-line description',
        'Select a suitable SSH key from the SSH agent.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_LENGTH_HELP_TEXT = commented(
        'The metavar is Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.',
    )(
        'Label :: Help text :: One-line description',
        'Ensure a passphrase length of {metavar} characters.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_LOWER_HELP_TEXT = commented(
        'The metavar is Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.',
    )(
        'Label :: Help text :: One-line description',
        'Ensure at least {metavar} lowercase characters.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_NOTES_HELP_TEXT = commented(
        'The metavar is Label.VAULT_METAVAR_SERVICE.',
    )(
        'Label :: Help text :: One-line description',
        'With --config and {service_metavar}, spawn an editor to edit notes.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_NUMBER_HELP_TEXT = commented(
        'The metavar is Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.',
    )(
        'Label :: Help text :: One-line description',
        'Ensure at least {metavar} digits.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_OVERWRITE_HELP_TEXT = commented(
        'The corresponding option is displayed as '
        '"--overwrite-existing / --merge-existing", so you may want to '
        'hint that the default (merge) is the second of those options.',
    )(
        'Label :: Help text :: One-line description',
        'Overwrite or merge (default) the existing configuration.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_PHRASE_HELP_TEXT = commented(
        '',
    )(
        'Label :: Help text :: One-line description',
        'Prompt for a master passphrase.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_PRINT_NOTES_BEFORE_HELP_TEXT = commented(
        'The corresponding option is displayed as '
        '"--print-notes-before / --print-notes-after", so you may want to '
        'hint that the default (after) is the second of those options.',
    )(
        'Label :: Help text :: One-line description',
        'Print the service notes (if any) before or after (default) '
        'the existing configuration.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_REPEAT_HELP_TEXT = commented(
        'The metavar is Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.',
    )(
        'Label :: Help text :: One-line description',
        'Forbid any run of {metavar} identical characters.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_SPACE_HELP_TEXT = commented(
        'The metavar is Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.',
    )(
        'Label :: Help text :: One-line description',
        'Ensure at least {metavar} spaces.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_SYMBOL_HELP_TEXT = commented(
        'The metavar is Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.',
    )(
        'Label :: Help text :: One-line description',
        'Ensure at least {metavar} symbol characters.',
        flags='python-brace-format',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_UNSET_HELP_TEXT = commented(
        'The corresponding option is displayed as '
        '"--unset=phrase|key|...|symbol", so the "given setting" is '
        'referring to "phrase", "key", "lower", ..., or "symbol", '
        'respectively.  '
        '"with --config" here means that the user must also specify '
        '"--config" for this option to have any effect.',
    )(
        'Label :: Help text :: One-line description',
        'With --config, also unsets the given setting.  '
        'May be specified multiple times.',
    )
    """"""
    DERIVEPASSPHRASE_VAULT_UPPER_HELP_TEXT = commented(
        'The metavar is Label.PASSPHRASE_GENERATION_METAVAR_NUMBER.',
    )(
        'Label :: Help text :: One-line description',
        'Ensure at least {metavar} uppercase characters.',
        flags='python-brace-format',
    )
    """"""

    EXPORT_VAULT_FORMAT_DEFAULTS_HELP_TEXT = commented(
        'See EXPORT_VAULT_FORMAT_HELP_TEXT.  '
        'The format names/labels "v0.3", "v0.2" and "storeroom" '
        'should not be translated.',
    )(
        'Label :: Help text :: One-line description',
        'Default: v0.3, v0.2, storeroom.',
    )
    """"""
    EXPORT_VAULT_FORMAT_HELP_TEXT = commented(
        'The defaults_hint is Label.EXPORT_VAULT_FORMAT_DEFAULTS_HELP_TEXT, '
        'the metavar is Label.EXPORT_VAULT_FORMAT_METAVAR_FMT.',
    )(
        'Label :: Help text :: One-line description',
        'Try the following storage format {metavar}.  '
        'If specified multiple times, the '
        'formats will be tried in order.  '
        '{defaults_hint}',
        flags='python-brace-format',
    )
    """"""
    EXPORT_VAULT_KEY_DEFAULTS_HELP_TEXT = commented(
        'See EXPORT_VAULT_KEY_HELP_TEXT.',
    )(
        'Label :: Help text :: One-line description',
        'Default: check the VAULT_KEY, LOGNAME, USER, or USERNAME '
        'environment variables.',
    )
    """"""
    EXPORT_VAULT_KEY_HELP_TEXT = commented(
        'The defaults_hint is Label.EXPORT_VAULT_KEY_DEFAULTS_HELP_TEXT, '
        'the metavar is Label.EXPORT_VAULT_KEY_METAVAR_K.',
    )(
        'Label :: Help text :: One-line description',
        'Use {metavar} as the storage master key.  {defaults_hint}',
        flags='python-brace-format',
    )
    """"""
    HELP_OPTION_HELP_TEXT = commented(
        '',
    )(
        'Label :: Help text :: One-line description',
        'Show this help text, then exit.',
    )
    """"""
    QUIET_OPTION_HELP_TEXT = commented(
        '',
    )(
        'Label :: Help text :: One-line description',
        'Suppress even warnings; emit only errors.',
    )
    """"""
    VERBOSE_OPTION_HELP_TEXT = commented(
        '',
    )(
        'Label :: Help text :: One-line description',
        'Emit extra/progress information to standard error.',
    )
    """"""
    VERSION_OPTION_HELP_TEXT = commented(
        '',
    )(
        'Label :: Help text :: One-line description',
        'Show applicable version information, then exit.',
    )
    """"""
    COMMANDS_LABEL = commented(
        '',
    )(
        'Label :: Help text :: Option group name',
        'Commands',
    )
    """"""
    COMPATIBILITY_OPTION_LABEL = commented(
        '',
    )(
        'Label :: Help text :: Option group name',
        'Compatibility and extension options',
    )
    """"""
    CONFIGURATION_LABEL = commented(
        '',
    )(
        'Label :: Help text :: Option group name',
        'Configuration',
    )
    """"""
    LOGGING_LABEL = commented(
        '',
    )(
        'Label :: Help text :: Option group name',
        'Logging',
    )
    """"""
    OPTIONS_LABEL = commented(
        '',
    )(
        'Label :: Help text :: Option group name',
        'Options',
    )
    """"""
    OTHER_OPTIONS_LABEL = commented(
        '',
    )(
        'Label :: Help text :: Option group name',
        'Other options',
    )
    """"""
    PASSPHRASE_GENERATION_LABEL = commented(
        '',
    )(
        'Label :: Help text :: Option group name',
        'Passphrase generation',
    )
    """"""
    STORAGE_MANAGEMENT_LABEL = commented(
        '',
    )(
        'Label :: Help text :: Option group name',
        'Storage management',
    )
    """"""
    VERSION_INFO_TEXT = commented(
        '',
    )(
        'Label :: Info Message',
        '{PROG_NAME} {VERSION}',  # noqa: RUF027
        flags='python-brace-format',
    )
    """"""
    CONFIRM_THIS_CHOICE_PROMPT_TEXT = commented(
        'There is no support for "yes" or "no" in other languages '
        'than English, so it is advised that your translation makes it '
        'clear that only the strings "y", "yes", "n" or "no" are supported, '
        'even if the prompt becomes a bit longer.',
    )(
        'Label :: Interactive prompt',
        'Confirm this choice? (y/N)',
    )
    """"""
    SUITABLE_SSH_KEYS_LABEL = commented(
        'This label is the heading of the list of suitable SSH keys.',
    )(
        'Label :: Interactive prompt',
        'Suitable SSH keys:',
    )
    """"""
    YOUR_SELECTION_PROMPT_TEXT = commented(
        '',
    )(
        'Label :: Interactive prompt',
        'Your selection? (1-{n}, leave empty to abort)',
        flags='python-brace-format',
    )
    """"""


class DebugMsgTemplate(enum.Enum):
    """Debug messages for the `derivepassphrase` command-line."""

    BUCKET_ITEM_FOUND = commented(
        'This message is emitted by the vault configuration exporter '
        'for "storeroom"-type configuration directories.  '
        'The system stores entries in different "buckets" of a hash table.  '
        'Here, we report on a single item (path and value) we discovered '
        'after decrypting the whole bucket.  '
        '(We ensure the path and value are printable as-is.)',
    )(
        'Debug message',
        'Found bucket item: {path} -> {value}',
        flags='python-brace-format',
    )
    """"""
    DECRYPT_BUCKET_ITEM_INFO = commented(
        '"AES256-CBC" and "PKCS#7" are, in essence, names of formats, '
        'and should not be translated.  '
        '"IV" means "initialization vector", and is specifically '
        'a cryptographic term, as are "plaintext" and "ciphertext".',
    )(
        'Debug message',
        """\
Decrypt bucket item contents:

  \b
  Encryption key (master key): {enc_key}
  Encryption cipher: AES256-CBC with PKCS#7 padding
  Encryption IV: {iv}
  Encrypted ciphertext: {ciphertext}
  Plaintext: {plaintext}
""",
        flags='python-brace-format',
    )
    """"""
    DECRYPT_BUCKET_ITEM_KEY_INFO = commented(
        '',
    )(
        'Debug message',
        """\
Decrypt bucket item:

  \b
  Plaintext: {plaintext}
  Encryption key (master key): {enc_key}
  Signing key (master key): {sign_key}
""",
        flags='python-brace-format',
    )
    """"""
    DECRYPT_BUCKET_ITEM_MAC_INFO = commented(
        'The MAC stands for "message authentication code", '
        'which guarantees the authenticity of the message to anyone '
        'who holds the corresponding key, similar to a digital signature.  '
        'The acronym "MAC" is assumed to be well-known to the '
        'English target audience, or at least discoverable by them; '
        'they *are* asking for debug output, after all.  '
        'Please use your judgement as to whether to translate this term '
        'or not, expanded or not.',
    )(
        'Debug message',
        """\
Decrypt bucket item contents:

  \b
  MAC key: {sign_key}
  Authenticated content: {ciphertext}
  Claimed MAC value: {claimed_mac}
  Computed MAC value: {actual_mac}
""",
        flags='python-brace-format',
    )
    """"""
    DECRYPT_BUCKET_ITEM_SESSION_KEYS_INFO = commented(
        '"AES256-CBC" and "PKCS#7" are, in essence, names of formats, '
        'and should not be translated.  '
        '"IV" means "initialization vector", and is specifically '
        'a cryptographic term, as are "plaintext" and "ciphertext".',
    )(
        'Debug message',
        """\
Decrypt bucket item session keys:

  \b
  Encryption key (master key): {enc_key}
  Encryption cipher: AES256-CBC with PKCS#7 padding
  Encryption IV: {iv}
  Encrypted ciphertext: {ciphertext}
  Plaintext: {plaintext}
  Parsed plaintext: {code}
""",
        flags='python-brace-format',
    )
    """"""
    DECRYPT_BUCKET_ITEM_SESSION_KEYS_MAC_INFO = commented(
        'The MAC stands for "message authentication code", '
        'which guarantees the authenticity of the message to anyone '
        'who holds the corresponding key, similar to a digital signature.  '
        'The acronym "MAC" is assumed to be well-known to the '
        'English target audience, or at least discoverable by them; '
        'they *are* asking for debug output, after all.  '
        'Please use your judgement as to whether to translate this term '
        'or not, expanded or not.',
    )(
        'Debug message',
        """\
Decrypt bucket item session keys:

  \b
  MAC key (master key): {sign_key}
  Authenticated content: {ciphertext}
  Claimed MAC value: {claimed_mac}
  Computed MAC value: {actual_mac}
""",
        flags='python-brace-format',
    )
    """"""
    DERIVED_MASTER_KEYS_KEYS = commented(
        '',
    )(
        'Debug message',
        """\
Derived master keys' keys:

  \b
  Encryption key: {enc_key}
  Signing key: {sign_key}
  Password: {pw_bytes}
  Function call: pbkdf2(algorithm={algorithm!r}, length={length!r}, salt={salt!r}, iterations={iterations!r})
""",  # noqa: E501
        flags='python-brace-format',
    )
    """"""
    DIRECTORY_CONTENTS_CHECK_OK = commented(
        'This message is emitted by the vault configuration exporter '
        'for "storeroom"-type configuration directories, '
        'while "assembling" the items stored in the configuration '
        """according to the item's "path".  """
        'Each "directory" in the path contains a list of children '
        'it claims to contain, and this list must be matched '
        'against the actual discovered items.  '
        'Now, at the end, we actually confirm the claim.  '
        '(We would have already thrown an error here otherwise.)',
    )(
        'Debug message',
        'Directory contents check OK: {path} -> {contents}',
        flags='python-brace-format',
    )
    """"""
    MASTER_KEYS_DATA_MAC_INFO = commented(
        'The MAC stands for "message authentication code", '
        'which guarantees the authenticity of the message to anyone '
        'who holds the corresponding key, similar to a digital signature.  '
        'The acronym "MAC" is assumed to be well-known to the '
        'English target audience, or at least discoverable by them; '
        'they *are* asking for debug output, after all.  '
        'Please use your judgement as to whether to translate this term '
        'or not, expanded or not.',
    )(
        'Debug message',
        """\
Master keys data:

  \b
  MAC key: {sign_key}
  Authenticated content: {ciphertext}
  Claimed MAC value: {claimed_mac}
  Computed MAC value: {actual_mac}
""",
        flags='python-brace-format',
    )
    """"""
    POSTPONING_DIRECTORY_CONTENTS_CHECK = commented(
        'This message is emitted by the vault configuration exporter '
        'for "storeroom"-type configuration directories, '
        'while "assembling" the items stored in the configuration '
        """according to the item's "path".  """
        'Each "directory" in the path contains a list of children '
        'it claims to contain, and this list must be matched '
        'against the actual discovered items.  '
        'When emitting this message, we merely indicate that we saved '
        'the "claimed" list for this directory for later.',
    )(
        'Debug message',
        'Postponing directory contents check: {path} -> {contents}',
        flags='python-brace-format',
    )
    """"""
    SETTING_CONFIG_STRUCTURE_CONTENTS = commented(
        'This message is emitted by the vault configuration exporter '
        'for "storeroom"-type configuration directories, '
        'while "assembling" the items stored in the configuration '
        """according to the item's "path".  """
        'We confirm that we set the entry at the given path '
        'to the given value.',
    )(
        'Debug message',
        'Setting contents: {path} -> {value}',
        flags='python-brace-format',
    )
    """"""
    SETTING_CONFIG_STRUCTURE_CONTENTS_EMPTY_DIRECTORY = commented(
        'This message is emitted by the vault configuration exporter '
        'for "storeroom"-type configuration directories, '
        'while "assembling" the items stored in the configuration '
        """according to the item's "path".  """
        'We confirm that we set up a currently empty directory '
        'at the given path.',
    )(
        'Debug message',
        'Setting contents (empty directory): {path}',
        flags='python-brace-format',
    )
    """"""
    VAULT_NATIVE_CHECKING_MAC_DETAILS = commented(
        'This message is emitted by the vault configuration exporter '
        'for "native"-type configuration directories.  '
        'It is preceded by the info message '
        'VAULT_NATIVE_PARSING_IV_PAYLOAD_MAC; see the commentary there '
        'concerning the terms and thoughts on translating them.',
    )(
        'Debug message',
        """\
MAC details:

  \b
  MAC input: {mac_input}
  Expected MAC: {mac}
""",
        flags='python-brace-format',
    )
    """"""
    VAULT_NATIVE_EVP_BYTESTOKEY_INIT = commented(
        'This message is emitted by the vault configuration exporter '
        'for "native"-type configuration directories: '
        'in v0.2, the non-standard and deprecated "EVP_bytestokey" function '
        'from OpenSSL must be reimplemented from scratch.  '
        'The terms "salt" and "IV" (initialization vector) '
        'are cryptographic terms.',
    )(
        'Debug message',
        """\
evp_bytestokey_md5 (initialization):

  \b
  Input: {data}
  Salt: {salt}
  Key size: {key_size}
  IV size: {iv_size}
  Buffer length: {buffer_length}
  Buffer: {buffer}
""",
        flags='python-brace-format',
    )
    """"""
    VAULT_NATIVE_EVP_BYTESTOKEY_RESULT = commented(
        'This message is emitted by the vault configuration exporter '
        'for "native"-type configuration directories: '
        'in v0.2, the non-standard and deprecated "EVP_bytestokey" function '
        'from OpenSSL must be reimplemented from scratch.  '
        'The terms "salt" and "IV" (initialization vector) '
        'are cryptographic terms.'
        'This function reports on the final results.',
    )(
        'Debug message',
        """\
evp_bytestokey_md5 (result):

  \b
  Encryption key: {enc_key}
  IV: {iv}
""",
        flags='python-brace-format',
    )
    """"""
    VAULT_NATIVE_EVP_BYTESTOKEY_ROUND = commented(
        'This message is emitted by the vault configuration exporter '
        'for "native"-type configuration directories: '
        'in v0.2, the non-standard and deprecated "EVP_bytestokey" function '
        'from OpenSSL must be reimplemented from scratch.  '
        'The terms "salt" and "IV" (initialization vector) '
        'are cryptographic terms.'
        'This function reports on the updated buffer length and contents '
        'after executing one round of hashing.',
    )(
        'Debug message',
        """\
evp_bytestokey_md5 (round update):

  \b
  Buffer length: {buffer_length}
  Buffer: {buffer}
""",
        flags='python-brace-format',
    )
    """"""
    VAULT_NATIVE_PADDED_PLAINTEXT = commented(
        'This message is emitted by the vault configuration exporter '
        'for "native"-type configuration directories.  '
        '"padding" and "plaintext" are cryptographic terms.',
    )(
        'Debug message',
        'Padded plaintext: {contents}',
        flags='python-brace-format',
    )
    """"""
    VAULT_NATIVE_PARSE_BUFFER = commented(
        'This message is emitted by the vault configuration exporter '
        'for "native"-type configuration directories.  '
        'It is preceded by the info message '
        'VAULT_NATIVE_PARSING_IV_PAYLOAD_MAC; see the commentary there '
        'concerning the terms and thoughts on translating them.',
    )(
        'Debug message',
        """\
Buffer: {contents}

  \b
  IV: {iv}
  Payload: {payload}
  MAC: {mac}
""",
        flags='python-brace-format',
    )
    """"""
    VAULT_NATIVE_PBKDF2_CALL = commented(
        '',
    )(
        'Debug message',
        """\
Master key derivation:

  \b
  PBKDF2 call: PBKDF2-HMAC(password={password!r}, salt={salt!r}, iterations={iterations!r}, key_size={key_size!r}, algorithm={algorithm!r})
  Result (binary): {raw_result}
  Result (hex key): {result_key!r}
""",  # noqa: E501
        flags='python-brace-format',
    )
    """"""
    VAULT_NATIVE_PLAINTEXT = commented(
        'This message is emitted by the vault configuration exporter '
        'for "native"-type configuration directories.  '
        '"plaintext" is a cryptographic term.',
    )(
        'Debug message',
        'Plaintext: {contents}',
        flags='python-brace-format',
    )
    """"""
    VAULT_NATIVE_V02_PAYLOAD_MAC_POSTPROCESSING = commented(
        'This message is emitted by the vault configuration exporter '
        'for "native"-type configuration directories.  '
        'It is preceded by the info message '
        'VAULT_NATIVE_PARSING_IV_PAYLOAD_MAC and the debug message '
        'PARSING_NATIVE_PARSE_BUFFER; see the commentary there concerning '
        'the terms and thoughts on translating them.',
    )(
        'Debug message',
        """\
Postprocessing buffer (v0.2):

  \b
  Payload: {payload} (decoded from base64)
  MAC: {mac} (decoded from hex)
""",
        flags='python-brace-format',
    )
    """"""


class InfoMsgTemplate(enum.Enum):
    """Info messages for the `derivepassphrase` command-line."""

    ASSEMBLING_CONFIG_STRUCTURE = commented(
        'This message is emitted by the vault configuration exporter '
        'for "storeroom"-type configuration directories.  '
        'The system stores entries in different "buckets" of a hash table.  '
        'After the respective items in the buckets have been decrypted, '
        'we then have a list of item paths plus contents to populate.  '
        "This must be done in a certain order (we don't yet have an "
        'existing directory tree to rely on, but rather must '
        'build it on-the-fly), hence the term "assembling".',
    )(
        'Info message',
        'Assembling config structure',
    )
    """"""
    CANNOT_LOAD_AS_VAULT_CONFIG = commented(
        '"fmt" is a string such as "v0.2" or "storeroom", '
        'indicating the format which we tried to load the '
        'vault configuration as.',
    )(
        'Info message',
        'Cannot load {path!r} as a {fmt} vault configuration.',
        flags='python-brace-format',
    )
    """"""
    CHECKING_CONFIG_STRUCTURE_CONSISTENCY = commented(
        'This message is emitted by the vault configuration exporter '
        'for "storeroom"-type configuration directories.  '
        'Having "assembled" the configuration items according to '
        'their claimed paths and contents, we then check if the '
        'assembled structure is internally consistent.',
    )(
        'Info message',
        'Checking config structure consistency',
    )
    """"""
    DECRYPTING_BUCKET = commented(
        'This message is emitted by the vault configuration exporter '
        'for "storeroom"-type configuration directories.  '
        'The system stores entries in different "buckets" of a hash table.  '
        'We parse the directory bucket by bucket.  '
        'All buckets are numbered in hexadecimal, and typically there are '
        '32 buckets, so 2-digit hex numbers.',
    )(
        'Info message',
        'Decrypting bucket {bucket_number}',
        flags='python-brace-format',
    )
    """"""
    PARSING_MASTER_KEYS_DATA = commented(
        'This message is emitted by the vault configuration exporter '
        'for "storeroom"-type configuration directories.  '
        '`.keys` is a filename, from which data about the master keys '
        'for this configuration are loaded.',
    )(
        'Info message',
        'Parsing master keys data from .keys',
    )
    """"""
    PIP_INSTALL_EXTRA = commented(
        'This message immediately follows an error message about '
        'a missing library that needs to be installed.  '
        'The Python Package Index (PyPI) supports declaring sets of '
        'optional dependencies as "extras", so users installing from PyPI '
        'can request reinstallation with a named "extra" being enabled.  '
        'This would then let the installer take care of the '
        'missing libraries automatically, '
        'hence this suggestion to PyPI users.',
    )(
        'Info message',
        'For users installing from PyPI, see the {extra_name!r} extra.',
        flags='python-brace-format',
    )
    """"""
    SUCCESSFULLY_MIGRATED = commented(
        'This info message immediately follows the '
        '"Using deprecated v0.1-style ..." deprecation warning.',
    )(
        'Info message',
        'Successfully migrated to {path!r}.',
        flags='python-brace-format',
    )
    """"""
    VAULT_NATIVE_CHECKING_MAC = commented(
        '',
    )(
        'Info message',
        'Checking MAC',
    )
    """"""
    VAULT_NATIVE_DECRYPTING_CONTENTS = commented(
        '',
    )(
        'Info message',
        'Decrypting contents',
    )
    """"""
    VAULT_NATIVE_DERIVING_KEYS = commented(
        '',
    )(
        'Info message',
        'Deriving an encryption and signing key',
    )
    """"""
    VAULT_NATIVE_PARSING_IV_PAYLOAD_MAC = commented(
        'This message is emitted by the vault configuration exporter '
        'for "native"-type configuration directories.  '
        '"IV" means "initialization vector", and "MAC" means '
        '"message authentication code".  '
        'They are specifically cryptographic terms, as is "payload".  '
        'The acronyms "IV" and "MAC" are assumed to be well-known to the '
        'English target audience, or at least discoverable by them; '
        'they *are* asking for debug output, after all.  '
        'Please use your judgement as to whether to translate these terms '
        'or not, expanded or not.',
    )(
        'Info message',
        'Parsing IV, payload and MAC from the file contents',
    )
    """"""


class WarnMsgTemplate(enum.Enum):
    """Warning messages for the `derivepassphrase` command-line."""

    EDITING_NOTES_BUT_NOT_STORING_CONFIG = commented(
        '',
    )(
        'Warning message',
        'Specifying --notes without --config is ineffective.  '
        'No notes will be edited.',
    )
    EMPTY_SERVICE_NOT_SUPPORTED = commented(
        '',
    )(
        'Warning message',
        'An empty {service_metavar} is not supported by vault(1).  '
        'For compatibility, this will be treated as if '
        '{service_metavar} was not supplied, i.e., it will error out, '
        'or operate on global settings.',
        flags='python-brace-format',
    )
    """"""
    EMPTY_SERVICE_SETTINGS_INACCESSIBLE = commented(
        '',
    )(
        'Warning message',
        'An empty {service_metavar} is not supported by vault(1).  '
        'The empty-string service settings will be inaccessible '
        'and ineffective.  '
        'To ensure that vault(1) and {PROG_NAME} see the settings, '  # noqa: RUF027
        'move them into the "global" section.',
        flags='python-brace-format',
    )
    """"""
    FAILED_TO_MIGRATE_CONFIG = commented(
        '"error" is supplied by the operating system (errno/strerror).',
    )(
        'Warning message',
        'Failed to migrate to {path!r}: {error}: {filename!r}.',
        flags='python-brace-format',
    )
    """"""
    GLOBAL_PASSPHRASE_INEFFECTIVE = commented(
        '',
    )(
        'Warning message',
        'Setting a global passphrase is ineffective '
        'because a key is also set.',
    )
    """"""
    LEGACY_EDITOR_INTERFACE_NOTES_BACKUP = commented(
        '',
    )(
        'Warning message',
        'A backup copy of the old notes was saved to {filename!r}.  '
        'This is a safeguard against editing mistakes, because the '
        'vault(1)-compatible legacy editor interface does not allow '
        'aborting mid-edit, and because the notes were actually changed.',
        flags='python-brace-format',
    )
    PASSPHRASE_NOT_NORMALIZED = commented(
        'The key is a (vault) configuration key, in JSONPath syntax, '
        'typically "$.global" for the global passphrase or '
        '"$.services.service_name" or "$.services["service with spaces"]" '
        'for the services "service_name" and "service with spaces", '
        'respectively.  '
        'The form is one of the four Unicode normalization forms: '
        'NFC, NFD, NFKC, NFKD.  '
        'The asterisks are not special.  '
        'Please feel free to substitute any other appropriate way to '
        'mark up emphasis of the word "displays".',
    )(
        'Warning message',
        'The {key} passphrase is not {form}-normalized.  '
        'Its serialization as a byte string may not be what you '
        'expect it to be, even if it *displays* correctly.  '
        'Please make sure to double-check any derived passphrases '
        'for unexpected results.',
        flags='python-brace-format',
    )
    """"""
    SERVICE_NAME_INCOMPLETABLE = commented(
        '',
    )(
        'Warning message',
        'The service name {service!r} contains an ASCII control character, '
        'which is not supported by our shell completion code.  '
        'This service name will therefore not be available for completion '
        'on the command-line.  '
        'You may of course still type it in manually in whatever format '
        'your shell accepts, but we highly recommend choosing a different '
        'service name instead.',
        flags='python-brace-format',
    )
    """"""
    SERVICE_PASSPHRASE_INEFFECTIVE = commented(
        'The key that is set need not necessarily be set at the '
        'service level; it may be a global key as well.',
    )(
        'Warning message',
        'Setting a service passphrase is ineffective '
        'because a key is also set: {service}.',
        flags='python-brace-format',
    )
    """"""
    STEP_REMOVE_INEFFECTIVE_VALUE = commented(
        '',
    )(
        'Warning message',
        'Removing ineffective setting {path} = {old}.',
        flags='python-brace-format',
    )
    """"""
    STEP_REPLACE_INVALID_VALUE = commented(
        '',
    )(
        'Warning message',
        'Replacing invalid value {old} for key {path} with {new}.',
        flags='python-brace-format',
    )
    """"""
    V01_STYLE_CONFIG = commented(
        '',
    )(
        'Warning message :: Deprecation',
        'Using deprecated v0.1-style config file {old!r}, '
        'instead of v0.2-style {new!r}.  '
        'Support for v0.1-style config filenames will be removed in v1.0.',
        flags='python-brace-format',
    )
    """"""
    V10_SUBCOMMAND_REQUIRED = commented(
        'This deprecation warning may be issued at any level, '
        'i.e. we may actually be talking about subcommands, '
        'or sub-subcommands, or sub-sub-subcommands, etc., '
        'which is what the "here" is supposed to indicate.',
    )(
        'Warning message :: Deprecation',
        'A subcommand will be required here in v1.0.  '
        'See --help for available subcommands.  '
        'Defaulting to subcommand "vault".',
    )
    """"""


class ErrMsgTemplate(enum.Enum):
    """Error messages for the `derivepassphrase` command-line."""

    AGENT_REFUSED_LIST_KEYS = commented(
        '"loaded keys" being keys loaded into the agent.',
    )(
        'Error message',
        'The SSH agent failed to or refused to supply a list of loaded keys.',
    )
    """"""
    AGENT_REFUSED_SIGNATURE = commented(
        'The message to be signed is the vault UUID, '
        "but there's no space to explain that here, "
        'so ideally the error message does not go into detail.',
    )(
        'Error message',
        'The SSH agent failed to or refused to issue a signature '
        'with the selected key, necessary for deriving a service passphrase.',
    )
    """"""
    CANNOT_CONNECT_TO_AGENT = commented(
        '"error" is supplied by the operating system (errno/strerror).',
    )(
        'Error message',
        'Cannot connect to the SSH agent: {error}: {filename!r}.',
        flags='python-brace-format',
    )
    """"""
    CANNOT_DECODEIMPORT_VAULT_SETTINGS = commented(
        '"error" is supplied by the operating system (errno/strerror).',
    )(
        'Error message',
        'Cannot import vault settings: cannot decode JSON: {error}.',
        flags='python-brace-format',
    )
    """"""
    CANNOT_EXPORT_VAULT_SETTINGS = commented(
        '"error" is supplied by the operating system (errno/strerror).',
    )(
        'Error message',
        'Cannot export vault settings: {error}: {filename!r}.',
        flags='python-brace-format',
    )
    """"""
    CANNOT_IMPORT_VAULT_SETTINGS = commented(
        '"error" is supplied by the operating system (errno/strerror).',
    )(
        'Error message',
        'Cannot import vault settings: {error}: {filename!r}.',
        flags='python-brace-format',
    )
    """"""
    CANNOT_LOAD_USER_CONFIG = commented(
        '"error" is supplied by the operating system (errno/strerror).',
    )(
        'Error message',
        'Cannot load user config: {error}: {filename!r}.',
        flags='python-brace-format',
    )
    """"""
    CANNOT_LOAD_VAULT_SETTINGS = commented(
        '"error" is supplied by the operating system (errno/strerror).',
    )(
        'Error message',
        'Cannot load vault settings: {error}: {filename!r}.',
        flags='python-brace-format',
    )
    """"""
    CANNOT_PARSE_AS_VAULT_CONFIG = commented(
        'Unlike the "Cannot load {path!r} as a {fmt} '
        'vault configuration." message, *this* error message is emitted '
        'when we have tried loading the path in each of our '
        'supported formats, and failed.  '
        'The user will thus see the above "Cannot load ..." warning message '
        'potentially multiple times, '
        'and this error message at the very bottom.',
    )(
        'Error message',
        'Cannot parse {path!r} as a valid vault-native '
        'configuration file/directory.',
        flags='python-brace-format',
    )
    """"""
    CANNOT_PARSE_AS_VAULT_CONFIG_OSERROR = commented(
        '"error" is supplied by the operating system (errno/strerror).',
    )(
        'Error message',
        r'Cannot parse {path!r} as a valid vault-native '
        'configuration file/directory: {error}: {filename!r}.',
        flags='python-brace-format',
    )
    """"""
    CANNOT_STORE_VAULT_SETTINGS = commented(
        '"error" is supplied by the operating system (errno/strerror).',
    )(
        'Error message',
        'Cannot store vault settings: {error}: {filename!r}.',
        flags='python-brace-format',
    )
    """"""
    CANNOT_UNDERSTAND_AGENT = commented(
        'This error message is used whenever we cannot make '
        'any sense of a response from the SSH agent '
        'because the response is ill-formed '
        '(truncated, improperly encoded, etc.) '
        'or otherwise violates the communications protocol.  '
        'Well-formed responses that adhere to the protocol, '
        'even if they indicate that the requested operation failed, '
        'are handled with a different error message.',
    )(
        'Error message',
        "Cannot understand the SSH agent's response because it "
        'violates the communication protocol.',
    )
    """"""
    CANNOT_UPDATE_SETTINGS_NO_SETTINGS = commented(
        'The settings_type metavar contains translations for '
        'either "global settings" or "service-specific settings"; '
        'see the CANNOT_UPDATE_SETTINGS_METAVAR_SETTINGS_TYPE_GLOBAL and '
        'CANNOT_UPDATE_SETTINGS_METAVAR_SETTINGS_TYPE_SERVICE entries.  '
        'The first sentence will thus read either '
        '"Cannot update the global settings without any given settings." or '
        '"Cannot update the service-specific settings without any '
        'given settings.".  '
        'You may update this entry, and the two metavar entries, '
        'in any way you see fit that achieves the desired translations '
        'of the first sentence.',
    )(
        'Error message',
        'Cannot update the {settings_type} without any given settings.  '
        'You must specify at least one of --lower, ..., --symbol, --notes, '
        'or --phrase or --key.',
        flags='python-brace-format',
    )
    """"""
    INVALID_USER_CONFIG = commented(
        '"error" is supplied by the operating system (errno/strerror).',
    )(
        'Error message',
        'The user configuration file is invalid.  {error}: {filename!r}.',
        flags='python-brace-format',
    )
    """"""
    INVALID_VAULT_CONFIG = commented(
        'This error message is a reaction to a validator function '
        'saying *that* the configuration is not valid, '
        'but not *how* it is not valid.  '
        'The configuration file is principally parsable, however.',
    )(
        'Error message',
        'Invalid vault config: {config!r}.',
        flags='python-brace-format',
    )
    """"""
    MISSING_MODULE = commented(
        '',
    )(
        'Error message',
        'Cannot load the required Python module {module!r}.',
        flags='python-brace-format',
    )
    """"""
    NO_AF_UNIX = commented(
        '',
    )(
        'Error message',
        'Cannot connect to an SSH agent because this Python version '
        'does not support UNIX domain sockets.',
    )
    """"""
    NO_KEY_OR_PHRASE = commented(
        '',
    )(
        'Error message',
        'No passphrase or key was given in the configuration.  '
        'In this case, the --phrase or --key argument is required.',
    )
    """"""
    NO_SSH_AGENT_FOUND = commented(
        '',
    )(
        'Error message',
        'Cannot find any running SSH agent because SSH_AUTH_SOCK is not set.',
    )
    """"""
    NO_SUITABLE_SSH_KEYS = commented(
        '',
    )(
        'Error message',
        'The SSH agent contains no keys suitable for {PROG_NAME}.',  # noqa: RUF027
        flags='python-brace-format',
    )
    """"""
    PARAMS_MUTUALLY_EXCLUSIVE = commented(
        'The params are long-form command-line option names.  '
        'Typical example: "--key is mutually exclusive with --phrase."',
    )(
        'Error message',
        '{param1} is mutually exclusive with {param2}.',
        flags='python-brace-format',
    )
    """"""
    PARAMS_NEEDS_SERVICE = commented(
        'The param is a long-form command-line option name, '
        'the metavar is Label.VAULT_METAVAR_SERVICE.',
    )(
        'Error message',
        '{param} requires a {service_metavar}.',
        flags='python-brace-format',
    )
    """"""
    PARAMS_NEEDS_SERVICE_OR_CONFIG = commented(
        'The param is a long-form command-line option name, '
        'the metavar is Label.VAULT_METAVAR_SERVICE.',
    )(
        'Error message',
        '{param} requires a {service_metavar} or --config.',
        flags='python-brace-format',
    )
    """"""
    PARAMS_NO_SERVICE = commented(
        'The param is a long-form command-line option name, '
        'the metavar is Label.VAULT_METAVAR_SERVICE.',
    )(
        'Error message',
        '{param} does not take a {service_metavar} argument.',
        flags='python-brace-format',
    )
    """"""
    SERVICE_REQUIRED = commented(
        'The metavar is Label.VAULT_METAVAR_SERVICE.',
    )(
        'Error message',
        'Deriving a passphrase requires a {service_metavar}.',
        flags='python-brace-format',
    )
    """"""
    SET_AND_UNSET_SAME_SETTING = commented(
        'The rephrasing '
        '"Attempted to unset and set the same setting '
        '(--unset={setting} --{setting}=...) at the same time."'
        'may or may not be more suitable as a basis for translation instead.',
    )(
        'Error message',
        'Attempted to unset and set --{setting} at the same time.',
        flags='python-brace-format',
    )
    """"""
    SSH_KEY_NOT_LOADED = commented(
        '',
    )(
        'Error message',
        'The requested SSH key is not loaded into the agent.',
    )
    """"""
    USER_ABORTED_EDIT = commented(
        'The user requested to edit the notes for a service, '
        'but aborted the request mid-editing.',
    )(
        'Error message',
        'Not saving any new notes: the user aborted the request.',
    )
    """"""
    USER_ABORTED_PASSPHRASE = commented(
        'The user was prompted for a master passphrase, '
        'but aborted the request.',
    )(
        'Error message',
        'No passphrase was given; the user aborted the request.',
    )
    """"""
    USER_ABORTED_SSH_KEY_SELECTION = commented(
        'The user was prompted to select a master SSH key, '
        'but aborted the request.',
    )(
        'Error message',
        'No SSH key was selected; the user aborted the request.',
    )
    """"""


MsgTemplate: TypeAlias = Union[
    Label,
    DebugMsgTemplate,
    InfoMsgTemplate,
    WarnMsgTemplate,
    ErrMsgTemplate,
]
"""A type alias for all enums containing translatable strings as values."""
MSG_TEMPLATE_CLASSES = (
    Label,
    DebugMsgTemplate,
    InfoMsgTemplate,
    WarnMsgTemplate,
    ErrMsgTemplate,
)
"""A collection all enums containing translatable strings as values."""

DebugTranslations._load_cache()  # noqa: SLF001


def _write_po_file(  # noqa: C901,PLR0912
    fileobj: TextIO,
    /,
    *,
    is_template: bool = True,
    version: str = VERSION,
    build_time: datetime.datetime | None = None,
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
    if build_time is None and os.environ.get('SOURCE_DATE_EPOCH'):
        try:
            source_date_epoch = int(os.environ['SOURCE_DATE_EPOCH'])
        except ValueError as exc:
            err_msg = 'Cannot parse SOURCE_DATE_EPOCH'
            raise RuntimeError(err_msg) from exc
        else:
            build_time = datetime.datetime.fromtimestamp(
                source_date_epoch,
                tz=datetime.timezone.utc,
            )
    elif build_time is None:
        build_time = datetime.datetime.now().astimezone()
    if is_template:
        header = (
            inspect.cleandoc(rf"""
            # English translation for {PROG_NAME}.
            # Copyright (C) {build_time.strftime('%Y')} AUTHOR
            # This file is distributed under the same license as {PROG_NAME}.
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
            # English debug translation for {PROG_NAME}.
            # Copyright (C) {build_time.strftime('%Y')} {AUTHOR}
            # This file is distributed under the same license as {PROG_NAME}.
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
            'Last-Translator': AUTHOR,
            'Language': 'en_US@DEBUG',
            'Language-Team': 'English',
        })
    print(*_format_po_info(po_info), sep='\n', end='\n', file=fileobj)

    context_class = {
        'Label': Label,
        'Debug message': DebugMsgTemplate,
        'Info message': InfoMsgTemplate,
        'Warning message': WarnMsgTemplate,
        'Error message': ErrMsgTemplate,
    }

    def _sort_position_msg_template_class(
        item: tuple[str, Any],
        /,
    ) -> tuple[int, str]:
        context_type = item[0].split(' :: ')[0]
        return (
            MSG_TEMPLATE_CLASSES.index(context_class[context_type]),
            item[0],
        )

    for _ctx, subdict in sorted(
        entries.items(), key=_sort_position_msg_template_class
    ):
        for _msg, enum_value in sorted(
            subdict.items(), key=lambda kv: str(kv[1])
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
        line = f'{key}: {value}\n'
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

    def validate_build_time(value: str | None) -> datetime.datetime | None:
        if value is None:
            return None
        ret = datetime.datetime.fromisoformat(value)
        if ret.isoformat(sep=' ', timespec='seconds') != value:
            raise ValueError(f'invalid time specification: {value}')  # noqa: EM102,TRY003
        return ret

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
        default=VERSION,
        help='Override declared software version',
    )
    ap.add_argument(
        '--set-build-time',
        action='store',
        dest='build_time',
        default=None,
        type=validate_build_time,
        help='Override the time of build (YYYY-MM-DD HH:MM:SS+HH:MM format, '
        'default: $SOURCE_DATE_EPOCH, or the current time)',
    )
    args = ap.parse_args()
    _write_po_file(
        sys.stdout,
        version=args.version,
        is_template=args.is_template,
        build_time=args.build_time,
    )
