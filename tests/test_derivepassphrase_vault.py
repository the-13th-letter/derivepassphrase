# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Test passphrase generation via derivepassphrase.vault.Vault."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

import hypothesis
import pytest
from hypothesis import strategies
from typing_extensions import TypeAlias, TypeVar

import derivepassphrase
import tests

if TYPE_CHECKING:
    from collections.abc import Iterator

Vault: TypeAlias = derivepassphrase.vault.Vault


class TestVault:
    phrase = b'She cells C shells bye the sea shoars'
    google_phrase = rb': 4TVH#5:aZl8LueOT\{'
    twitter_phrase = rb"[ (HN_N:lI&<ro=)3'g9"

    @pytest.mark.parametrize(
        ['service', 'expected'],
        [
            (b'google', google_phrase),
            ('twitter', twitter_phrase),
        ],
    )
    def test_200_basic_configuration(
        self, service: bytes | str, expected: bytes
    ) -> None:
        assert Vault(phrase=self.phrase).generate(service) == expected

    def test_201_phrase_dependence(self) -> None:
        assert (
            Vault(phrase=(self.phrase + b'X')).generate('google')
            == b'n+oIz6sL>K*lTEWYRO%7'
        )

    def test_202_reproducibility_and_bytes_service_name(self) -> None:
        assert Vault(phrase=self.phrase).generate(b'google') == Vault(
            phrase=self.phrase
        ).generate('google')

    def test_203_reproducibility_and_bytearray_service_name(self) -> None:
        assert Vault(phrase=self.phrase).generate(b'google') == Vault(
            phrase=self.phrase
        ).generate(bytearray(b'google'))

    def test_210_nonstandard_length(self) -> None:
        assert (
            Vault(phrase=self.phrase, length=4).generate('google') == b'xDFu'
        )

    def test_211_repetition_limit(self) -> None:
        assert (
            Vault(
                phrase=b'', length=24, symbol=0, number=0, repeat=1
            ).generate('asd')
            == b'IVTDzACftqopUXqDHPkuCIhV'
        )

    def test_212_without_symbols(self) -> None:
        assert (
            Vault(phrase=self.phrase, symbol=0).generate('google')
            == b'XZ4wRe0bZCazbljCaMqR'
        )

    def test_213_no_numbers(self) -> None:
        assert (
            Vault(phrase=self.phrase, number=0).generate('google')
            == b'_*$TVH.%^aZl(LUeOT?>'
        )

    def test_214_no_lowercase_letters(self) -> None:
        assert (
            Vault(phrase=self.phrase, lower=0).generate('google')
            == b':{?)+7~@OA:L]!0E$)(+'
        )

    def test_215_at_least_5_digits(self) -> None:
        assert (
            Vault(phrase=self.phrase, length=8, number=5).generate('songkick')
            == b'i0908.7['
        )

    def test_216_lots_of_spaces(self) -> None:
        assert (
            Vault(phrase=self.phrase, space=12).generate('songkick')
            == b' c   6 Bq  % 5fR    '
        )

    def test_217_all_character_classes(self) -> None:
        assert (
            Vault(
                phrase=self.phrase,
                lower=2,
                upper=2,
                number=1,
                space=3,
                dash=2,
                symbol=1,
            ).generate('google')
            == b': : fv_wqt>a-4w1S  R'
        )

    def test_218_only_numbers_and_very_high_repetition_limit(self) -> None:
        generated = Vault(
            phrase=b'',
            length=40,
            lower=0,
            upper=0,
            space=0,
            dash=0,
            symbol=0,
            repeat=4,
        ).generate('abcdef')
        forbidden_substrings = {
            b'0000',
            b'1111',
            b'2222',
            b'3333',
            b'4444',
            b'5555',
            b'6666',
            b'7777',
            b'8888',
            b'9999',
        }
        for substring in forbidden_substrings:
            assert substring not in generated

    def test_219_very_limited_character_set(self) -> None:
        generated = Vault(
            phrase=b'', length=24, lower=0, upper=0, space=0, symbol=0
        ).generate('testing')
        assert generated == b'763252593304946694588866'

    def test_220_character_set_subtraction(self) -> None:
        assert Vault._subtract(b'be', b'abcdef') == bytearray(b'acdf')

    @pytest.mark.parametrize(
        ['length', 'settings', 'entropy'],
        [
            (20, {}, math.log2(math.factorial(20)) + 20 * math.log2(94)),
            (
                20,
                {'upper': 0, 'number': 0, 'space': 0, 'symbol': 0},
                math.log2(math.factorial(20)) + 20 * math.log2(26),
            ),
            (0, {}, float('-inf')),
            (
                0,
                {'lower': 0, 'number': 0, 'space': 0, 'symbol': 0},
                float('-inf'),
            ),
            (1, {}, math.log2(94)),
            (1, {'upper': 0, 'lower': 0, 'number': 0, 'symbol': 0}, 0.0),
        ],
    )
    def test_221_entropy(
        self, length: int, settings: dict[str, int], entropy: int
    ) -> None:
        v = Vault(length=length, **settings)  # type: ignore[arg-type]
        assert math.isclose(v._entropy(), entropy)
        assert v._estimate_sufficient_hash_length() > 0
        if math.isfinite(entropy) and entropy:
            assert v._estimate_sufficient_hash_length(1.0) == math.ceil(
                entropy / 8
            )
        assert v._estimate_sufficient_hash_length(8.0) >= entropy

    def test_222_hash_length_estimation(self) -> None:
        v = Vault(
            phrase=self.phrase,
            lower=0,
            upper=0,
            number=0,
            symbol=0,
            space=1,
            length=1,
        )
        assert v._entropy() == 0.0
        assert v._estimate_sufficient_hash_length() > 0

    @pytest.mark.parametrize(
        ['service', 'expected'],
        [
            (b'google', google_phrase),
            ('twitter', twitter_phrase),
        ],
    )
    def test_223_hash_length_expansion(
        self,
        monkeypatch: pytest.MonkeyPatch,
        service: str | bytes,
        expected: bytes,
    ) -> None:
        v = Vault(phrase=self.phrase)
        monkeypatch.setattr(
            v,
            '_estimate_sufficient_hash_length',
            lambda *args, **kwargs: 1,  # noqa: ARG005
        )
        assert v._estimate_sufficient_hash_length() < len(self.phrase)
        assert v.generate(service) == expected

    @pytest.mark.parametrize(
        's',
        [
            'ñ',
            'Düsseldorf',
            'liberté, egalité, fraternité',
            'ASCII',
            b'D\xc3\xbcsseldorf',
            bytearray([2, 3, 5, 7, 11, 13]),
        ],
    )
    def test_224_binary_strings(self, s: str | bytes | bytearray) -> None:
        binstr = Vault._get_binary_string
        if isinstance(s, str):
            assert binstr(s) == s.encode('UTF-8')
            assert binstr(binstr(s)) == s.encode('UTF-8')
        else:
            assert binstr(s) == bytes(s)
            assert binstr(binstr(s)) == bytes(s)

    def test_310_too_many_symbols(self) -> None:
        with pytest.raises(
            ValueError, match='requested passphrase length too short'
        ):
            Vault(phrase=self.phrase, symbol=100)

    def test_311_no_viable_characters(self) -> None:
        with pytest.raises(ValueError, match='no allowed characters left'):
            Vault(
                phrase=self.phrase,
                lower=0,
                upper=0,
                number=0,
                space=0,
                dash=0,
                symbol=0,
            )

    def test_320_character_set_subtraction_duplicate(self) -> None:
        with pytest.raises(ValueError, match='duplicate characters'):
            Vault._subtract(b'abcdef', b'aabbccddeeff')
        with pytest.raises(ValueError, match='duplicate characters'):
            Vault._subtract(b'aabbccddeeff', b'abcdef')

    def test_322_hash_length_estimation(self) -> None:
        v = Vault(phrase=self.phrase)
        with pytest.raises(ValueError, match='invalid safety factor'):
            assert v._estimate_sufficient_hash_length(-1.0)
        with pytest.raises(
            TypeError, match='invalid safety factor: not a float'
        ):
            assert v._estimate_sufficient_hash_length(None)  # type: ignore[arg-type]


class TestHypotheses:
    @tests.hypothesis_settings_coverage_compatible
    @hypothesis.given(
        phrase=strategies.one_of(
            strategies.binary(min_size=1), strategies.text(min_size=1)
        ),
        config=tests.vault_full_service_config(),
        service=strategies.text(min_size=1),
    )
    # regression test
    @hypothesis.example(
        phrase=b'\x00',
        config={
            'lower': 0,
            'upper': 0,
            'number': 0,
            'space': 2,
            'dash': 0,
            'symbol': 1,
            'repeat': 2,
            'length': 3,
        },
        service='0',
    )
    # regression test
    @hypothesis.example(
        phrase=b'\x00',
        config={
            'lower': 0,
            'upper': 0,
            'number': 0,
            'space': 1,
            'dash': 0,
            'symbol': 0,
            'repeat': 9,
            'length': 5,
        },
        service='0',
    )
    # branch coverage: case `repeat = 0` in `if config[repeat]` below
    @hypothesis.example(
        phrase=b'\x00',
        config={
            'lower': 0,
            'upper': 0,
            'number': 0,
            'space': 1,
            'dash': 0,
            'symbol': 0,
            'repeat': 0,
            'length': 5,
        },
        service='0',
    )
    def test_100_all_length_character_and_occurrence_constraints_satisfied(
        self,
        phrase: str | bytes,
        config: dict[str, int],
        service: str,
    ) -> None:
        try:
            password = Vault(phrase=phrase, **config).generate(service)
        except ValueError as exc:
            if 'no allowed characters left' in exc.args:
                return
            raise  # pragma: no cover
        n = len(password)
        assert n == config['length'], 'Password has wrong length.'
        for key in ('lower', 'upper', 'number', 'space', 'dash', 'symbol'):
            if config[key] > 0:
                assert (
                    sum(c in Vault._CHARSETS[key] for c in password)
                    >= config[key]
                ), (
                    'Password does not satisfy '
                    'character occurrence constraints.'
                )
            elif key in {'dash', 'symbol'}:
                # Character classes overlap, so "forbidden" characters may
                # appear via the other character class.
                assert True
            else:
                assert (
                    sum(c in Vault._CHARSETS[key] for c in password) == 0
                ), 'Password does not satisfy character ban constraints.'

        T = TypeVar('T', str, bytes)

        def length_r_substrings(string: T, *, r: int) -> Iterator[T]:
            for i in range(len(string) - (r - 1)):
                yield string[i : i + r]

        repeat = config['repeat']
        if repeat:
            for snippet in length_r_substrings(password, r=(repeat + 1)):
                assert (
                    len(set(snippet)) > 1
                ), 'Password does not satisfy character repeat constraints.'

    @tests.hypothesis_settings_coverage_compatible
    @hypothesis.given(
        phrase=strategies.one_of(
            strategies.binary(min_size=1, max_size=100),
            strategies.text(
                min_size=1,
                max_size=100,
                alphabet=strategies.characters(max_codepoint=255),
            ),
        ),
        length=strategies.integers(min_value=1, max_value=200),
        service=strategies.text(min_size=1, max_size=100),
    )
    def test_101_password_with_length(
        self,
        phrase: str | bytes,
        length: int,
        service: str,
    ) -> None:
        password = Vault(phrase=phrase, length=length).generate(service)
        assert len(password) == length

    # This test has time complexity `O(length * repeat)`, both of which
    # are chosen by hypothesis and thus outside our control.
    @hypothesis.settings(deadline=None)
    @hypothesis.given(
        phrase=strategies.one_of(
            strategies.binary(min_size=1, max_size=100),
            strategies.text(
                min_size=1,
                max_size=100,
                alphabet=strategies.characters(max_codepoint=255),
            ),
        ),
        length=strategies.integers(min_value=2, max_value=200),
        repeat=strategies.integers(min_value=1, max_value=200),
        service=strategies.text(min_size=1, max_size=1000),
    )
    def test_102_password_with_repeat(
        self,
        phrase: str | bytes,
        length: int,
        repeat: int,
        service: str,
    ) -> None:
        password = Vault(phrase=phrase, length=length, repeat=repeat).generate(
            service
        )
        for i in range((length + 1) - (repeat + 1)):
            assert len(set(password[i : i + repeat + 1])) > 1
