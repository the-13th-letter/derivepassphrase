# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
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
import sys
import textwrap
import types
from typing import TYPE_CHECKING, NamedTuple, TextIO, cast

import derivepassphrase as dpp

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from typing_extensions import Any, Self

__author__ = dpp.__author__
__version__ = dpp.__version__

__all__ = ('PROG_NAME',)

PROG_NAME = 'derivepassphrase'


def load_translations(
    localedirs: list[str] | None = None,
    languages: Sequence[str] | None = None,
    class_: type[gettext.NullTranslations] | None = None,
) -> gettext.NullTranslations:
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
    def maybe_rewrap(string: str) -> str:
        string = inspect.cleandoc(string)
        if not any(s.strip() == '\b' for s in string.splitlines()):
            string = '\n'.join(
                textwrap.wrap(
                    string,
                    width=float('inf'),  # type: ignore[arg-type]
                    fix_sentence_endings=True,
                )
            )
        else:  # pragma: no cover
            string = ''.join(
                s
                for s in string.splitlines(True)  # noqa: FBT003
                if s.strip() == '\b'
            )
        return string

    msg = maybe_rewrap(msg)
    plural_msg = maybe_rewrap(plural_msg)
    context = context.strip()
    comments = inspect.cleandoc(comments)
    flags = (
        frozenset(f.strip() for f in flags)
        if not isinstance(flags, str)
        else frozenset({flags})
    )
    assert '{' not in msg or bool(
        flags & {'python-brace-format', 'no-python-brace-format'}
    ), f'Missing flag for how to deal with brace in {msg!r}'
    assert '%' not in msg or bool(
        flags & {'python-format', 'no-python-format'}
    ), f'Missing flag for how to deal with percent character in {msg!r}'
    assert (
        not flags & {'python-format', 'python-brace-format'}
        or '%' in msg
        or '{' in msg
    ), f'Missing format string parameters in {msg!r}'
    return TranslatableString(msg, plural_msg, context, comments, flags)


class TranslatedString:
    def __init__(
        self,
        template: (
            str
            | TranslatableString
            | Label
            | InfoMsgTemplate
            | WarnMsgTemplate
            | ErrMsgTemplate
        ),
        args_dict: Mapping[str, Any] = types.MappingProxyType({}),
        /,
        **kwargs: Any,  # noqa: ANN401
    ) -> None:
        if isinstance(
            template, (Label, InfoMsgTemplate, WarnMsgTemplate, ErrMsgTemplate)
        ):
            template = cast(TranslatableString, template.value)
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
            self._rendered = template.format(**self.kwargs)
        return self._rendered

    def maybe_without_filename(self) -> Self:
        if (
            not isinstance(self.template, str)
            and self.kwargs.get('filename') is None
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


class Label(enum.Enum):
    DEPRECATION_WARNING_LABEL = _prepare_translatable(
        'Deprecation warning', comments='', context='diagnostic label'
    )
    WARNING_LABEL = _prepare_translatable(
        'Warning', comments='', context='diagnostic label'
    )
    DERIVEPASSPHRASE_01 = _prepare_translatable(
        msg="""
        Derive a strong passphrase, deterministically, from a master secret.
        """,
        comments='',
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
        msg="""
        Export a foreign configuration to standard output.
        """,
        comments='',
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
        msg="""
        Export a vault-native configuration to standard output.
        """,
        comments='',
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
        msg="""
        Derive a passphrase using the vault derivation scheme.
        """,
        comments='',
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
        msg='(Deprecated) {text}',
        comments='',
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
    )
    CANNOT_UPDATE_SETTINGS_NO_SETTINGS = _prepare_translatable(
        msg=r"""
        Cannot update {settings_type!s} settings without any given
        settings.  You must specify at least one of --lower, ...,
        --symbol, or --phrase or --key.
        """,
        comments='',
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


def write_pot_file(fileobj: TextIO) -> None:
    r"""Write a .po template to the given file object.

    Assumes the file object is opened for writing and accepts string
    inputs.  The file will *not* be closed when writing is complete.
    The file *must* be opened in UTF-8 encoding, lest the file will
    declare an incorrect encoding.

    This function crucially depends on all translatable strings
    appearing in the enums of this module.  Certain parts of the
    .po header are hard-coded, as is the source filename.

    """
    entries: dict[
        str,
        dict[
            str,
            Label | InfoMsgTemplate | WarnMsgTemplate | ErrMsgTemplate,
        ],
    ] = {}
    for enum_class in (
        Label,
        InfoMsgTemplate,
        WarnMsgTemplate,
        ErrMsgTemplate,
    ):
        for member in enum_class.__members__.values():
            ctx = member.value.l10n_context
            msg = member.value.singular
            if (
                msg in entries.setdefault(ctx, {})
                and entries[ctx][msg] != member
            ):
                raise AssertionError(  # noqa: DOC501,TRY003
                    f'Duplicate entry for ({ctx!r}, {msg!r}): '  # noqa: EM102
                    f'{entries[ctx][msg]!r} and {member!r}'
                )
            entries[ctx][msg] = member
    now = datetime.datetime.now().astimezone()
    header = (
        inspect.cleandoc(rf"""
        # English translation for {PROG_NAME!s}.
        # Copyright (C) {now.strftime('%Y')} AUTHOR
        # This file is distributed under the same license as {PROG_NAME!s}.
        # AUTHOR <someone@example.com>, {now.strftime('%Y')}.
        #
        msgid ""
        msgstr ""
        "Project-Id-Version: {PROG_NAME!s} {__version__!s}\n"
        "Report-Msgid-Bugs-To: software@the13thletter.info\n"
        "POT-Creation-Date: {now.strftime('%Y-%m-%d %H:%M%z')}\n"
        "PO-Revision-Date: {now.strftime('%Y-%m-%d %H:%M%z')}\n"
        "Last-Translator: AUTHOR <someone@example.com>\n"
        "Language: en\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=UTF-8\n"
        "Content-Transfer-Encoding: 8bit\n"
        "Plural-Forms: nplurals=2; plural=(n != 1);\n"
        """).removesuffix('\n')
        + '\n'
    )
    fileobj.write(header)
    for _ctx, subdict in sorted(entries.items()):
        for _msg, enum_value in sorted(
            subdict.items(),
            key=lambda kv: str(kv[1]),
        ):
            fileobj.writelines(_format_po_entry(enum_value))


def _format_po_entry(
    enum_value: Label | InfoMsgTemplate | WarnMsgTemplate | ErrMsgTemplate,
) -> tuple[str, ...]:
    ret: list[str] = ['\n']
    ts = enum_value.value
    if ts.translator_comments:
        ret.extend(
            f'#. {line}\n'
            for line in ts.translator_comments.splitlines(False)  # noqa: FBT003
        )
    ret.append(f'#: derivepassphrase/_cli_msg.py:{enum_value}\n')
    if ts.flags:
        ret.append(f'#, {", ".join(sorted(ts.flags))}\n')
    if ts.l10n_context:
        ret.append(f'msgctxt {_cstr(ts.l10n_context)}\n')
    ret.append(f'msgid {_cstr(ts.singular)}\n')
    if ts.plural:
        ret.append(f'msgid_plural {_cstr(ts.plural)}\n')
    ret.append('msgstr ""\n')
    return tuple(ret)


def _cstr(s: str) -> str:
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
        for line in s.splitlines(True)  # noqa: FBT003
    )


if __name__ == '__main__':
    write_pot_file(sys.stdout)
