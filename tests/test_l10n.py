# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Test the localization machinery."""

from __future__ import annotations

import contextlib
import errno
import gettext
import os
import re
import string
import types
from typing import TYPE_CHECKING, cast

import hypothesis
import pytest
from hypothesis import strategies

from derivepassphrase._internals import cli_messages as msg

if TYPE_CHECKING:
    from collections.abc import Iterator


class Parametrize(types.SimpleNamespace):
    MAYBE_FORMAT_STRINGS = pytest.mark.parametrize(
        's', ['{spam}', '{spam}abc', '{', '}', '{{{']
    )


all_translatable_strings_dict: dict[
    msg.TranslatableString,
    msg.MsgTemplate,
] = {}
for enum_class in msg.MSG_TEMPLATE_CLASSES:
    all_translatable_strings_dict.update({
        cast('msg.TranslatableString', v.value): v for v in enum_class
    })

all_translatable_strings_enum_values = tuple(
    sorted(all_translatable_strings_dict.values(), key=str)
)
all_translatable_strings = [
    cast('msg.TranslatableString', v.value)
    for v in all_translatable_strings_enum_values
]


@pytest.fixture(scope='class')
def use_debug_translations() -> Iterator[None]:
    """Force the use of debug translations (pytest class fixture)."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(msg, 'translation', msg.DebugTranslations())
        yield


@contextlib.contextmanager
def monkeypatched_null_translations() -> Iterator[None]:
    """Force the use of no-op translations in this context."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(msg, 'translation', gettext.NullTranslations())
        yield


@pytest.mark.usefixtures('use_debug_translations')
class TestL10nMachineryWithDebugTranslations:
    """Test the localization machinery together with debug translations."""

    error_codes = tuple(
        sorted(errno.errorcode, key=errno.errorcode.__getitem__)
    )
    """A cache of the known error codes from the [`errno`][] module."""
    known_fields_error_messages = tuple(
        e
        for e in sorted(msg.ErrMsgTemplate, key=str)
        if e.value.fields() == ['error', 'filename']
    )
    """
    A cache of known error messages that contain both `error` and
    `filename` replacement fields.
    """
    no_fields_messages = tuple(
        e for e in all_translatable_strings_enum_values if not e.value.fields()
    )
    """A cache of known messages that don't contain replacement fields."""

    @hypothesis.given(value=strategies.text(max_size=100))
    @hypothesis.example('{')
    def test_100_debug_translation_get_str(self, value: str) -> None:
        """Translating a raw string object does nothing."""
        translated = msg.translation.gettext(value)
        assert translated == value

    @hypothesis.given(value=strategies.sampled_from(all_translatable_strings))
    def test_100a_debug_translation_get_ts(
        self,
        value: msg.TranslatableString,
    ) -> None:
        """Translating a TranslatableString translates and interpolates."""
        ts_name = str(all_translatable_strings_dict[value])
        context = value.l10n_context
        singular = value.singular
        translated = msg.translation.pgettext(context, singular)
        assert translated.startswith(ts_name)
        suffix = translated.removeprefix(ts_name)
        assert not suffix or suffix.startswith('(')

    @hypothesis.given(
        value=strategies.sampled_from(all_translatable_strings_enum_values)
    )
    def test_100b_debug_translation_get_enum(
        self,
        value: msg.MsgTemplate,
    ) -> None:
        """Translating a MsgTemplate operates on the enum value."""
        ts_name = str(value)
        inner_value = cast('msg.TranslatableString', value.value)
        context = inner_value.l10n_context
        singular = inner_value.singular
        translated = msg.translation.pgettext(context, singular)
        assert translated.startswith(ts_name)
        suffix = translated.removeprefix(ts_name)
        assert not suffix or suffix.startswith('(')

    @hypothesis.given(value=strategies.text(max_size=100))
    @hypothesis.example('{')
    def test_100c_debug_translation_get_ts_str(self, value: str) -> None:
        """Translating a constant TranslatableString does nothing."""
        translated = msg.TranslatedString.constant(value)
        assert str(translated) == value

    @hypothesis.given(
        values=strategies.lists(
            strategies.sampled_from(no_fields_messages),
            min_size=2,
            max_size=2,
            unique=True,
        )
    )
    def test_101_translated_strings_operations(
        self,
        values: list[msg.MsgTemplate],
    ) -> None:
        """TranslatableStrings are hashable."""
        assert len(values) == 2
        ts0 = msg.TranslatedString(values[0])
        ts1 = msg.TranslatedString(values[0])
        ts2 = msg.TranslatedString(values[1])
        assert ts0 == ts1
        assert ts0 != ts2
        assert ts1 != ts2
        strings = {ts0}
        strings.add(ts1)
        assert len(strings) == 1
        strings.add(ts2)
        assert len(strings) == 2

    @hypothesis.given(
        value=strategies.sampled_from(known_fields_error_messages),
        errnos=strategies.lists(
            strategies.sampled_from(error_codes),
            min_size=2,
            max_size=2,
            unique=True,
        ),
    )
    def test_101a_translated_strings_operations_interpolated(
        self,
        value: msg.ErrMsgTemplate,
        errnos: list[int],
    ) -> None:
        """TranslatableStrings are hashable even with interpolations."""
        assert len(errnos) == 2
        error1, error2 = [os.strerror(c) for c in errnos]
        # The Annoying OS has error codes with identical strerror values.
        hypothesis.assume(error1 != error2)
        ts1 = msg.TranslatedString(
            value, error=error1, filename=None
        ).maybe_without_filename()
        ts2 = msg.TranslatedString(
            value, error=error2, filename=None
        ).maybe_without_filename()
        assert str(ts1) != str(ts2)
        assert ts1 != ts2
        assert len({ts1, ts2}) == 2

    @hypothesis.given(
        value=strategies.sampled_from(known_fields_error_messages),
        errno_=strategies.sampled_from(error_codes),
    )
    def test_101b_translated_strings_operations_interpolated(
        self,
        value: msg.ErrMsgTemplate,
        errno_: int,
    ) -> None:
        """Interpolated TranslatableStrings with error/filename are hashable."""
        error = os.strerror(errno_)
        # The debug translations specifically do *not* differ in output
        # when the filename is trimmed.  So we need to request some
        # other predictable, non-debug output.
        #
        # Also, because of the class-scoped fixture, and because
        # hypothesis interferes with a function-scoped fixture, we also
        # need to do our own manual monkeypatching here, separately, for
        # each hypothesis iteration.
        with monkeypatched_null_translations():
            ts0 = msg.TranslatedString(value, error=error, filename=None)
            ts1 = ts0.maybe_without_filename()
            assert str(ts0) != str(ts1)
            assert ts0 != ts1
            assert len({ts0, ts1}) == 2

    @Parametrize.MAYBE_FORMAT_STRINGS
    def test_102_translated_strings_suppressed_interpolation_fail(
        self,
        s: str,
    ) -> None:
        """TranslatableStrings require fixed replacement fields.

        They reject attempts at stringification if unknown fields are
        passed, or if fields are missing, or if the format string is
        invalid.

        """
        with monkeypatched_null_translations():
            ts1 = msg.TranslatedString(s)
            ts2 = msg.TranslatedString(s, spam='eggs')
            if '{spam}' in s:
                with pytest.raises(KeyError, match=r'spam'):
                    str(ts1)
                assert str(ts2) == s.replace('{spam}', 'eggs')
            else:
                # Known error message variations:
                #
                # * Single { encountered in the pattern string
                # * Single } encountered in the pattern string
                # * Single '{' encountered in the pattern string
                # * Single '}' encountered in the pattern string
                # * Single '{'
                # * Single '}'
                pattern = re.compile(
                    r"Single (?:\{|\}|'\{'|'\}')(?: encountered in the pattern string)?"
                )
                with pytest.raises(ValueError, match=pattern):
                    str(ts1)
                with pytest.raises(ValueError, match=pattern):
                    str(ts2)

    @hypothesis.given(
        s=strategies.text(
            strategies.sampled_from(string.ascii_lowercase + '{}'),
            min_size=1,
            max_size=20,
        )
    )
    def test_102a_translated_strings_suppressed_interpolation_str(
        self,
        s: str,
    ) -> None:
        """Constant TranslatedStrings don't interpolate fields."""
        with monkeypatched_null_translations():
            ts = msg.TranslatedString.constant(s)
            try:
                assert str(ts) == s
            except ValueError as exc:  # pragma: no cover
                # Not a test error (= test author's fault), but
                # a regression (= code under test is at fault).
                err_msg = 'Interpolation attempted'
                raise AssertionError(err_msg) from exc

    @hypothesis.given(
        s=strategies.text(
            strategies.sampled_from(string.ascii_lowercase + '{}'),
            min_size=1,
            max_size=20,
        )
    )
    def test_102b_translated_strings_suppressed_interpolation_ts_manual(
        self,
        s: str,
    ) -> None:
        """Non-format TranslatedStrings don't interpolate fields."""
        with monkeypatched_null_translations():
            ts_inner = msg.TranslatableString(
                '',
                '{spam}' + s,
                flags=frozenset({'no-python-brace-format'}),
            )
            ts = msg.TranslatedString(ts_inner, spam='eggs')
            try:
                assert str(ts) == '{spam}' + s
            except ValueError as exc:  # pragma: no cover
                # Not a test error (= test author's fault), but
                # a regression (= code under test is at fault).
                err_msg = 'Interpolation attempted'
                raise AssertionError(err_msg) from exc
