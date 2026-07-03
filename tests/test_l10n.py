# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Test the localization machinery."""

from __future__ import annotations

import contextlib
import errno
import gettext
import os
import re
import types
from typing import TYPE_CHECKING, TypeVar

import hypothesis
import pytest
from hypothesis import strategies

from derivepassphrase._internals import cli_messages as msg
from tests.machinery import hypothesis as hypothesis_machinery

if TYPE_CHECKING:
    from collections.abc import Generator
    from typing import ClassVar


class Parametrize(types.SimpleNamespace):
    MAYBE_FORMAT_STRINGS = hypothesis_machinery.explicit_examples(
        "s", ["{spam}", "{spam}abc", "{", "}", "{{{"]
    )


@pytest.fixture(scope="class")
def use_debug_translations() -> Generator[None, None, None]:
    """Force the use of debug translations (pytest class fixture)."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(msg, "translation", msg.DebugTranslations())
        yield


@contextlib.contextmanager
def monkeypatched_null_translations() -> Generator[None, None, None]:
    """Force the use of no-op translations in this context."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(msg, "translation", gettext.NullTranslations())
        yield


class Strategies:
    """`hypothesis` strategies for testing the localization machinery."""

    all_translatable_strings_dict: ClassVar[
        dict[
            msg.TranslatableString,
            msg.MsgTemplate,
        ]
    ] = {}
    for enum_class in msg.MSG_TEMPLATE_CLASSES:
        all_translatable_strings_dict.update({v.value: v for v in enum_class})

    all_translatable_strings_enum_values = tuple(
        sorted(all_translatable_strings_dict.values(), key=str)
    )
    all_translatable_strings = tuple(
        v.value for v in all_translatable_strings_enum_values
    )

    error_codes = tuple(
        sorted(errno.errorcode, key=errno.errorcode.__getitem__)
    )
    """A cache of the known error codes from the [`errno`][] module."""
    known_fields_error_messages = tuple(
        e
        for e in sorted(msg.ErrMsgTemplate, key=str)
        if e.value.fields() == ["error", "filename"]
    )
    """
    A cache of known error messages that contain both `error` and
    `filename` replacement fields.
    """
    no_fields_messages = tuple(
        e for e in all_translatable_strings_enum_values if not e.value.fields()
    )
    """A cache of known messages that don't contain replacement fields."""

    @classmethod
    def errnos(cls) -> strategies.SearchStrategy[int]:
        """Return a strategy for errno values."""
        return strategies.sampled_from(cls.error_codes)

    @classmethod
    def error_messages_with_fields(
        cls,
    ) -> strategies.SearchStrategy[msg.ErrMsgTemplate]:
        """Return a strategy for error messages with known replacement fields.

        All error messages from this strategy contain (only) the "error"
        and "filename" replacement fields.

        """
        return strategies.sampled_from(cls.known_fields_error_messages)

    @staticmethod
    def printable_strings() -> strategies.SearchStrategy[str]:
        """Return a strategy for printable strings."""
        return strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=100,
        )

    @classmethod
    def strings_without_fields(
        cls,
    ) -> strategies.SearchStrategy[msg.MsgTemplate]:
        """Return a strategy for messages without any replacement fields."""
        return strategies.sampled_from(cls.no_fields_messages)

    @classmethod
    def translatable_string_enums(
        cls,
    ) -> strategies.SearchStrategy[msg.MsgTemplate]:
        """Return a strategy for translatable message enum values."""
        return strategies.sampled_from(
            cls.all_translatable_strings_enum_values
        )

    @classmethod
    def translatable_strings(
        cls,
    ) -> strategies.SearchStrategy[msg.TranslatableString]:
        """Return a strategy for translatable messages."""
        return strategies.sampled_from(cls.all_translatable_strings)

    T = TypeVar("T")

    @staticmethod
    def two_different(
        strategy: strategies.SearchStrategy[T], /
    ) -> strategies.SearchStrategy[tuple[T, T]]:
        """Return a strategy for generating unique pairs of things.

        We assume the "things" strategy to generate hashable elements.

        Args:
            strategy:
                An existing search strategy.

        """
        return strategies.lists(
            strategy, min_size=2, max_size=2, unique=True
        ).map(tuple)  # type: ignore[arg-type]


@pytest.mark.usefixtures("use_debug_translations")
class TestDebugTranslations:
    """Test the localization machinery together with debug translations."""

    @staticmethod
    def _test_interpolated(
        ts_name: str, ts_value: msg.TranslatableString
    ) -> None:
        context = ts_value.l10n_context
        singular = ts_value.singular
        translated = msg.translation.pgettext(context, singular)
        assert translated.startswith(ts_name)
        suffix = translated.removeprefix(ts_name)
        assert not suffix or suffix.startswith("(")

    @hypothesis.given(value=Strategies.printable_strings())
    @hypothesis.example(value="{")
    def test_get_str(self, value: str) -> None:
        """Translating a raw string object does nothing."""
        translated = msg.translation.gettext(value)
        assert translated == value

    @hypothesis.given(value=Strategies.printable_strings())
    @hypothesis.example(value="{")
    def test_get_ts_str(self, value: str) -> None:
        """Translating a constant TranslatableString does nothing."""
        translated = msg.TranslatedString.constant(value)
        assert str(translated) == value

    @hypothesis.given(value=Strategies.translatable_strings())
    def test_get_ts(
        self,
        value: msg.TranslatableString,
    ) -> None:
        """Translating a TranslatableString translates and interpolates."""
        self._test_interpolated(
            str(Strategies.all_translatable_strings_dict[value]), value
        )

    @hypothesis.given(value=Strategies.translatable_string_enums())
    def test_get_enum(
        self,
        value: msg.MsgTemplate,
    ) -> None:
        """Translating a MsgTemplate operates on the enum value."""
        self._test_interpolated(str(value), value.value)


@pytest.mark.usefixtures("use_debug_translations")
class TestTranslatedStrings:
    """Test the translated string objects."""

    @hypothesis.given(
        values=Strategies.two_different(Strategies.strings_without_fields())
    )
    def test_hashable(
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
        value=Strategies.error_messages_with_fields(),
        errnos=Strategies.two_different(Strategies.errnos()),
    )
    def test_hashable_interpolated(
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
        value=Strategies.error_messages_with_fields(),
        errno_=Strategies.errnos(),
    )
    def test_hashable_interpolated_error_and_filename(
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


@pytest.mark.usefixtures("use_debug_translations")
class TestSuppressedInterpolations:
    """Test the interpolation suppression behavior of translated strings."""

    # TODO(the-13th-letter): Revise this test, in particular, the error
    # assertions.
    @Parametrize.MAYBE_FORMAT_STRINGS
    def test_missing_fields(self, s: str) -> None:
        """TranslatableStrings require fixed replacement fields.

        They reject attempts at stringification if unknown fields are
        passed, or if fields are missing, or if the format string is
        invalid.

        """
        with monkeypatched_null_translations():
            ts1 = msg.TranslatedString(s)
            ts2 = msg.TranslatedString(s, spam="eggs")
            if "{spam}" in s:
                with pytest.raises(KeyError, match=r"spam"):
                    str(ts1)
                assert str(ts2) == s.replace("{spam}", "eggs")
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

    @hypothesis.given(s=Strategies.printable_strings())
    def test_constant_strings(self, s: str) -> None:
        """Constant TranslatedStrings don't interpolate fields."""
        with monkeypatched_null_translations():
            ts = msg.TranslatedString.constant(s)
            try:
                assert str(ts) == s
            except ValueError as exc:  # pragma: no cover
                # Not a test error (= test author's fault), but
                # a regression (= code under test is at fault).
                err_msg = "Interpolation attempted"
                raise AssertionError(err_msg) from exc

    @hypothesis.given(s=Strategies.printable_strings())
    def test_nonformat_strings(self, s: str) -> None:
        """Non-format TranslatedStrings don't interpolate fields."""
        with monkeypatched_null_translations():
            ts_inner = msg.TranslatableString(
                "",
                "{spam}" + s,
                flags=frozenset({"no-python-brace-format"}),
            )
            ts = msg.TranslatedString(ts_inner, spam="eggs")
            try:
                assert str(ts) == "{spam}" + s
            except ValueError as exc:  # pragma: no cover
                # Not a test error (= test author's fault), but
                # a regression (= code under test is at fault).
                err_msg = "Interpolation attempted"
                raise AssertionError(err_msg) from exc
