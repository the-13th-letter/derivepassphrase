#!/usr/bin/python3
# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Check for diagnostic messages not emitted in the manpages."""

from __future__ import annotations

import pathlib
import re
import sys
from typing import TYPE_CHECKING, Literal, NewType, cast

sys.path.append(str(pathlib.Path(sys.argv[0]).resolve().parent.parent / 'src'))
from derivepassphrase._internals import cli_messages  # noqa: PLC2701

if TYPE_CHECKING:
    from collections.abc import Iterator

    EnumName = NewType('EnumName', str)
    DiagnosticText = NewType('DiagnosticText', str)

known_errors = cli_messages.ErrMsgTemplate.__members__
known_warnings = cli_messages.WarnMsgTemplate.__members__


def _replace_known_metavars(string: str) -> str:
    return (
        string.replace(
            '{service_metavar!s}',
            cli_messages.Label.VAULT_METAVAR_SERVICE.value.singular,
        )
        .replace('{PROG_NAME!s}', cli_messages.PROG_NAME)
        .replace('{settings_type!s}', 'global/service-specific settings')
    )


# Use a double negative in the name ("does not mismatch text") because
# this is an error condition check, and if the enum name doesn't exist
# (because the manpage is outdated), then there is no mismatch.  This is
# clearer (to me at least) than erroneously claiming that a missing text
# matches the desired pattern.
def _mismatches_text(
    pattern: re.Pattern[str],
    enum_name: EnumName,
    name_type: Literal['warning', 'error'],
) -> bool:
    while '.' in enum_name:
        enum_name = cast('EnumName', enum_name.partition('.')[2])
    try:
        enum_value = (
            known_errors[enum_name].value
            if name_type == 'error'
            else known_warnings[enum_name].value
        )
    except KeyError:
        # No text, so no mismatch.
        return False
    texts = {enum_value.singular, enum_value.plural} - {''}
    return not all(pattern.match(_replace_known_metavars(t)) for t in texts)


def _entries_from_text(
    text: DiagnosticText,
    enum_names: set[EnumName],
) -> Iterator[
    tuple[
        Literal['warning', 'error'],
        tuple[DiagnosticText, EnumName],
    ]
]:
    assert text not in manpage_documented_warnings
    assert text not in manpage_documented_errors
    pattern_parts = [
        '.*' if part == '%s' else re.escape(part)
        for part in re.split(r'(%s)', text)
    ]
    pattern = re.compile(''.join(pattern_parts))
    for name in enum_names:
        _class_name, dot, enum_entry = name.partition('.')
        assert dot == '.', f'Invalid enum name {name!r}'
        assert '.' not in enum_entry, f'Unsupported enum name {name!r}'
        if name.startswith('WarnMsgTemplate.'):
            assert not _mismatches_text(
                pattern, enum_name=name, name_type='warning'
            ), (
                f"Warning text for {name} doesn't match the manpage: "
                f'{text!r} -> {pattern.pattern!r}'
            )
            yield ('warning', (text, cast('EnumName', enum_entry)))
        if name.startswith('ErrMsgTemplate.'):
            assert not _mismatches_text(
                pattern, enum_name=name, name_type='error'
            ), (
                f"Error text for {name} doesn't match the manpage: "
                f'{text!r} -> {pattern.pattern!r}'
            )
            yield ('error', (text, cast('EnumName', enum_entry)))


def _check_manpage(
    path: pathlib.Path,
) -> Iterator[
    tuple[
        Literal['warning', 'error'],
        tuple[DiagnosticText, EnumName],
    ]
]:
    enum_names: set[EnumName] = set()

    for line in path.read_text(encoding='UTF-8').splitlines(keepends=False):
        if enum_names and line.startswith('.It '):
            # Some *roff escape sequences need to be undone.  This is not an
            # exhaustive list; new entries will be added based on the actual
            # manpages as the need arises.
            text = cast(
                'DiagnosticText',
                line.removeprefix('.It ').replace('"', '').replace(r'\-', '-'),
            )
            yield from _entries_from_text(text=text, enum_names=enum_names)
            enum_names.clear()
        elif line.startswith(r'.\" Message-ID (mark only):'):
            yield from _entries_from_mark_only(
                cast('EnumName', line.split(None, 4)[4])
            )
        elif line.startswith(r'.\" Message-ID:'):
            enum_names.add(cast('EnumName', line.split(None, 2)[2]))


def _entries_from_mark_only(
    name: EnumName,
) -> Iterator[
    tuple[
        Literal['warning', 'error'],
        tuple[DiagnosticText, EnumName],
    ]
]:
    text = cast('DiagnosticText', '<mark only>')
    _class_name, dot, enum_entry = name.partition('.')
    assert dot == '.', f'Invalid enum name {name!r}'
    assert '.' not in enum_entry, f'Unsupported enum name {name!r}'
    if name.startswith('WarnMsgTemplate.'):
        yield ('warning', (text, cast('EnumName', enum_entry)))
    if name.startswith('ErrMsgTemplate.'):
        yield ('error', (text, cast('EnumName', enum_entry)))


def _check_manpagedoc(
    path: pathlib.Path,
) -> Iterator[
    tuple[
        Literal['warning', 'error'],
        tuple[DiagnosticText, EnumName],
    ]
]:
    enum_names: set[EnumName] = set()

    for line in path.read_text(encoding='UTF-8').splitlines(keepends=False):
        if enum_names and line.startswith(('??? failure ', '??? warning ')):
            text = cast('DiagnosticText', line.split(None, 2)[2])
            for ch in ['"', '`']:
                assert text.startswith(ch)
                assert text.endswith(ch)
                text = cast('DiagnosticText', text[1:-1])
            yield from _entries_from_text(text=text, enum_names=enum_names)
            enum_names.clear()
        elif line.startswith('<!-- Message-ID (mark only):') and line.endswith(
            '-->'
        ):
            name = cast(
                'EnumName',
                line.removeprefix('<!-- Message-ID (mark only):')
                .removesuffix('-->')
                .strip(),
            )
            yield from _entries_from_mark_only(name)
        elif line.startswith('<!-- Message-ID:') and line.endswith('-->'):
            name = cast(
                'EnumName',
                line.removeprefix('<!-- Message-ID:')
                .removesuffix('-->')
                .strip(),
            )
            enum_names.add(name)


base = pathlib.Path(sys.argv[0]).resolve().parent.parent
manpage_documented_errors: dict[EnumName, DiagnosticText] = {}
manpage_documented_warnings: dict[EnumName, DiagnosticText] = {}
manpagedoc_documented_errors: dict[EnumName, DiagnosticText] = {}
manpagedoc_documented_warnings: dict[EnumName, DiagnosticText] = {}
for set_name, globs, errors, warnings in [
    (
        'manpages',
        sorted(pathlib.Path(base, 'man').glob('derivepassphrase*.1')),
        manpage_documented_errors,
        manpage_documented_warnings,
    ),
    (
        'manpage-ish docs',
        sorted(
            pathlib.Path(base, 'docs', 'reference').glob(
                'derivepassphrase*.1.md'
            )
        ),
        manpagedoc_documented_errors,
        manpagedoc_documented_warnings,
    ),
]:
    for path in globs:
        print(f'Checking manpage {path}', file=sys.stderr)
        checker = (
            _check_manpage if set_name == 'manpages' else _check_manpagedoc
        )
        for diagnostic_type, (text, name) in checker(path):
            if diagnostic_type == 'warning':
                warnings[name] = text
                print(
                    f'Found warning message {name!r} with {text!r} in manpage.',  # noqa: E501
                    file=sys.stderr,
                )
            else:
                errors[name] = text
                print(
                    f'Found error message {name!r} with {text!r} in manpage.',
                    file=sys.stderr,
                )
    assert set(errors) >= set(known_errors), (
        f"Some error messages aren't documented in the {set_name}: "
        + repr(set(known_errors) - set(errors))
    )
    assert set(warnings) >= set(known_warnings), (
        f"Some warning messages aren't documented in the {set_name}: "
        + repr(set(known_warnings) - set(warnings))
    )
    assert set(errors) <= set(known_errors), (
        f'Some unknown error messages are documented in the {set_name}: '
        + repr(set(errors) - set(known_errors))  # type: ignore[arg-type]
    )
    assert set(warnings) <= set(known_warnings), (
        f'Some unknown warning messages are documented in the {set_name}: '
        + repr(set(warnings) - set(known_warnings))  # type: ignore[arg-type]
    )

py_file_errors: set[EnumName] = set()
py_file_warnings: set[EnumName] = set()
match_errors_warnings = re.compile(
    r'\b(?:cli_messages|msg|_msg)\.(Err|Warn)MsgTemplate\.([A-Z0-9_]+)'
)
for path in pathlib.Path(base, 'src', 'derivepassphrase').glob('**/*.py'):
    if path != pathlib.Path(
        base, 'src', 'derivepassphrase', '_internals', 'cli_messages.py'
    ):
        filecontents = path.read_text(encoding='UTF-8')
        for match in match_errors_warnings.finditer(filecontents):
            message_type, symbol = match.group(1, 2)
            if message_type == 'Err':
                py_file_errors.add(cast('EnumName', symbol))
                print(
                    f'Found mention of error message {symbol} '
                    f'in source file {path!r}.',
                    file=sys.stderr,
                )
            elif message_type == 'Warn':
                py_file_warnings.add(cast('EnumName', symbol))
                print(
                    f'Found mention of warning message {symbol} '
                    f'in source file {path!r}.',
                    file=sys.stderr,
                )
if py_file_errors != set(known_errors):
    print(
        "Some error messages aren't in use: "
        + repr(set(known_errors) - py_file_errors),
        file=sys.stderr,
    )
if py_file_warnings != set(known_warnings):
    print(
        "Some warning messages aren't in use: "
        + repr(set(known_warnings) - py_file_warnings),
        file=sys.stderr,
    )
