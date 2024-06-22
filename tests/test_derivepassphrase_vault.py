# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Test passphrase generation via derivepassphrase.Vault."""

from __future__ import annotations

import math

import derivepassphrase
import sequin
import pytest

Vault = derivepassphrase.Vault
phrase = b'She cells C shells bye the sea shoars'
google_phrase = rb': 4TVH#5:aZl8LueOT\{'
twitter_phrase = rb"[ (HN_N:lI&<ro=)3'g9"

@pytest.mark.parametrize(['service', 'expected'], [
    (b'google', google_phrase),
    ('twitter', twitter_phrase),
])
def test_200_basic_configuration(service, expected):
    assert Vault(phrase=phrase).generate(service) == expected

def test_201_phrase_dependence():
    assert (
        Vault(phrase=(phrase + b'X')).generate('google') ==
        b'n+oIz6sL>K*lTEWYRO%7'
    )

def test_202_reproducibility_and_bytes_service_name():
    assert (
        Vault(phrase=phrase).generate(b'google') ==
        Vault(phrase=phrase).generate('google')
    )

def test_203_reproducibility_and_bytearray_service_name():
    assert (
        Vault(phrase=phrase).generate(b'google') ==
        Vault(phrase=phrase).generate(bytearray(b'google'))
    )

def test_210_nonstandard_length():
    assert Vault(phrase=phrase, length=4).generate('google') == b'xDFu'

def test_211_repetition_limit():
    assert (
        Vault(phrase=b'', length=24, symbol=0, number=0,
              repeat=1).generate('asd') ==
        b'IVTDzACftqopUXqDHPkuCIhV'
    )

def test_212_without_symbols():
    assert (
        Vault(phrase=phrase, symbol=0).generate('google') ==
        b'XZ4wRe0bZCazbljCaMqR'
    )

def test_213_too_many_symbols():
    with pytest.raises(ValueError,
                       match='requested passphrase length too short'):
        Vault(phrase=phrase, symbol=100)

def test_214_no_numbers():
    assert (
        Vault(phrase=phrase, number=0).generate('google') ==
        b'_*$TVH.%^aZl(LUeOT?>'
    )

def test_214_no_lowercase_letters():
    assert (
        Vault(phrase=phrase, lower=0).generate('google') ==
        b':{?)+7~@OA:L]!0E$)(+'
    )

def test_215_at_least_5_digits():
    assert (
        Vault(phrase=phrase, length=8, number=5).generate('songkick') ==
        b'i0908.7['
    )

def test_216_lots_of_spaces():
    assert (
        Vault(phrase=phrase, space=12).generate('songkick') ==
        b' c   6 Bq  % 5fR    '
    )

def test_217_no_viable_characters():
    with pytest.raises(ValueError,
                       match='no allowed characters left'):
        Vault(phrase=phrase, lower=0, upper=0, number=0,
              space=0, dash=0, symbol=0)

def test_218_all_character_classes():
    assert (
        Vault(phrase=phrase, lower=2, upper=2, number=1,
              space=3, dash=2, symbol=1).generate('google') ==
        b': : fv_wqt>a-4w1S  R'
    )

def test_219_only_numbers_and_very_high_repetition_limit():
    generated = Vault(phrase=b'', length=40, lower=0, upper=0, space=0,
                      dash=0, symbol=0, repeat=4).generate('abcdef')
    assert b'0000' not in generated
    assert b'1111' not in generated
    assert b'2222' not in generated
    assert b'3333' not in generated
    assert b'4444' not in generated
    assert b'5555' not in generated
    assert b'6666' not in generated
    assert b'7777' not in generated
    assert b'8888' not in generated
    assert b'9999' not in generated

def test_220_very_limited_character_set():
    generated = Vault(phrase=b'', length=24, lower=0, upper=0,
                      space=0, symbol=0).generate('testing')
    assert b'763252593304946694588866' == generated

def test_300_character_set_subtraction():
    assert Vault._subtract(b'be', b'abcdef') == bytearray(b'acdf')

def test_301_character_set_subtraction_duplicate():
    with pytest.raises(ValueError, match='duplicate characters'):
        Vault._subtract(b'abcdef', b'aabbccddeeff')
    with pytest.raises(ValueError, match='duplicate characters'):
        Vault._subtract(b'aabbccddeeff', b'abcdef')

@pytest.mark.parametrize(['length', 'settings', 'entropy'], [
    (20, {}, math.log2(math.factorial(20)) + 20 * math.log2(94)),
    (
        20,
        {'upper': 0, 'number': 0, 'space': 0, 'symbol': 0},
        math.log2(math.factorial(20)) + 20 * math.log2(26)
    ),
    (0, {}, float('-inf')),
    (0, {'lower': 0, 'number': 0, 'space': 0, 'symbol': 0}, float('-inf')),
    (1, {}, math.log2(94)),
    (1, {'upper': 0, 'lower': 0, 'number': 0, 'symbol': 0}, 0.0),
])
def test_400_entropy(
    length: int, settings: dict[str, int], entropy: int
) -> None:
    v = Vault(length=length, **settings)
    assert math.isclose(v._entropy(), entropy)
    assert v._estimate_sufficient_hash_length() > 0
    if math.isfinite(entropy) and entropy:
        assert v._estimate_sufficient_hash_length(1.0) == math.ceil(entropy / 8)
    assert v._estimate_sufficient_hash_length(8.0) >= entropy

def test_401_hash_length_estimation(
) -> None:
    v = Vault(phrase=phrase)
    with pytest.raises(ValueError,
                       match='invalid safety factor'):
        assert v._estimate_sufficient_hash_length(-1.0)
    with pytest.raises(TypeError,
                       match='invalid safety factor: not a float'):
        assert v._estimate_sufficient_hash_length(None)  # type: ignore
    v2 = Vault(phrase=phrase, lower=0, upper=0, number=0, symbol=0,
               space=1, length=1)
    assert v2._entropy() == 0.0
    assert v2._estimate_sufficient_hash_length() > 0

@pytest.mark.parametrize(['service', 'expected'], [
    (b'google', google_phrase),
    ('twitter', twitter_phrase),
])
def test_402_hash_length_expansion(
    monkeypatch: Any, service: str | bytes, expected: bytes
) -> None:
    v = Vault(phrase=phrase)
    monkeypatch.setattr(v,
                        '_estimate_sufficient_hash_length',
                        lambda *args, **kwargs: 1)
    assert v._estimate_sufficient_hash_length
    assert v.generate(service) == expected

@pytest.mark.parametrize(['s', 'raises'], [
    ('ñ', True), ('Düsseldorf', True),
    ('liberté, egalité, fraternité', True), ('ASCII', False),
    ('Düsseldorf'.encode('UTF-8'), False),
    (bytearray([2, 3, 5, 7, 11, 13]), False),
])
def test_403_binary_strings(s: str | bytes | bytearray, raises: bool) -> None:
    binstr = derivepassphrase.Vault._get_binary_string
    if raises:
        with pytest.raises(derivepassphrase.AmbiguousByteRepresentationError):
            binstr(s)
    elif isinstance(s, str):
        assert binstr(s) == s.encode('UTF-8')
        assert binstr(binstr(s)) == s.encode('UTF-8')
    else:
        assert binstr(s) == bytes(s)
        assert binstr(binstr(s)) == bytes(s)
