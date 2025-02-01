# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Test passphrase generation via derivepassphrase.vault.Vault."""

from __future__ import annotations

import array
import enum
import hashlib
import math
from typing import TYPE_CHECKING

import hypothesis
import pytest
from hypothesis import strategies
from typing_extensions import TypeVar

import tests
from derivepassphrase import vault

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from typing_extensions import Buffer

BLOCK_SIZE = hashlib.sha1().block_size
DIGEST_SIZE = hashlib.sha1().digest_size

PHRASE = b'She cells C shells bye the sea shoars'
"""The standard passphrase from <i>vault</i>(1)'s test suite."""
GOOGLE_PHRASE = rb': 4TVH#5:aZl8LueOT\{'
"""
The standard derived passphrase for the "google" service, from
<i>vault</i>(1)'s test suite.
"""
TWITTER_PHRASE = rb"[ (HN_N:lI&<ro=)3'g9"
"""
The standard derived passphrase for the "twitter" service, from
<i>vault</i>(1)'s test suite.
"""


class Parametrizations(enum.Enum):
    ENTROPY_RESULTS = pytest.mark.parametrize(
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
    BINARY_STRINGS = pytest.mark.parametrize(
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
    SAMPLE_SERVICES_AND_PHRASES = pytest.mark.parametrize(
        ['service', 'expected'],
        [
            (b'google', GOOGLE_PHRASE),
            ('twitter', TWITTER_PHRASE),
        ],
    )


def phrases_are_interchangable(
    phrase1: Buffer | str,
    phrase2: Buffer | str,
    /,
) -> bool:
    """Work-alike of [`vault.Vault.phrases_are_interchangable`][].

    This version is not resistant to timing attacks, but faster, and
    supports strings directly.

    Args:
        phrase1:
            A passphrase to compare.
        phrase2:
            A passphrase to compare.

    Returns:
        True if the phrases behave identically under [`vault.Vault`][],
        false otherwise.

    """

    def canon(bs: bytes, /) -> bytes:
        return (
            hashlib.sha1(bs).digest() + b'\x00' * (BLOCK_SIZE - DIGEST_SIZE)
            if len(bs) > BLOCK_SIZE
            else bs.rstrip(b'\x00')
        )

    phrase1 = canon(vault.Vault._get_binary_string(phrase1))
    phrase2 = canon(vault.Vault._get_binary_string(phrase2))
    return phrase1 == phrase2


class TestVault:
    """Test passphrase derivation with the "vault" scheme."""

    phrase = PHRASE

    @hypothesis.given(
        phrases=strategies.lists(
            strategies.binary(min_size=1, max_size=BLOCK_SIZE // 2),
            min_size=2,
            max_size=2,
            unique=True,
        ).filter(lambda tup: not phrases_are_interchangable(*tup)),
        service=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=BLOCK_SIZE // 2,
        ),
    )
    def test_100a_create_hash_phrase_dependence_small(
        self,
        phrases: list[bytes],
        service: str,
    ) -> None:
        """The internal hash is dependent on the master passphrase.

        We filter out interchangable passphrases during generation.

        """
        assert vault.Vault.create_hash(
            phrase=phrases[0], service=service
        ) != vault.Vault.create_hash(phrase=phrases[1], service=service)

    @hypothesis.given(
        phrases=strategies.lists(
            strategies.binary(min_size=BLOCK_SIZE, max_size=BLOCK_SIZE),
            min_size=2,
            max_size=2,
            unique=True,
        ).filter(lambda tup: not phrases_are_interchangable(*tup)),
        service=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=BLOCK_SIZE // 2,
        ),
    )
    def test_100b_create_hash_phrase_dependence_medium(
        self,
        phrases: list[bytes],
        service: str,
    ) -> None:
        """The internal hash is dependent on the master passphrase.

        We filter out interchangable passphrases during generation.

        """
        assert vault.Vault.create_hash(
            phrase=phrases[0], service=service
        ) != vault.Vault.create_hash(phrase=phrases[1], service=service)

    @hypothesis.given(
        phrases=strategies.lists(
            strategies.binary(
                min_size=BLOCK_SIZE + 1, max_size=BLOCK_SIZE + 8
            ),
            min_size=2,
            max_size=2,
            unique=True,
        ).filter(lambda tup: not phrases_are_interchangable(*tup)),
        service=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=BLOCK_SIZE // 2,
        ),
    )
    def test_100c_create_hash_phrase_dependence_large(
        self,
        phrases: tuple[bytes, bytes],
        service: str,
    ) -> None:
        """The internal hash is dependent on the master passphrase.

        We filter out interchangable passphrases during generation.

        """
        assert vault.Vault.create_hash(
            phrase=phrases[0], service=service
        ) != vault.Vault.create_hash(phrase=phrases[1], service=service)

    @hypothesis.given(
        phrases=strategies.lists(
            strategies.one_of(
                strategies.binary(min_size=1, max_size=BLOCK_SIZE // 2),
                strategies.binary(min_size=BLOCK_SIZE, max_size=BLOCK_SIZE),
                strategies.binary(
                    min_size=BLOCK_SIZE + 1, max_size=BLOCK_SIZE + 8
                ),
            ),
            min_size=2,
            max_size=2,
            unique=True,
        ).filter(lambda tup: not phrases_are_interchangable(*tup)),
        service=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=BLOCK_SIZE // 2,
        ),
    )
    def test_100d_create_hash_phrase_dependence_mixed(
        self,
        phrases: list[bytes],
        service: str,
    ) -> None:
        """The internal hash is dependent on the master passphrase.

        We filter out interchangable passphrases during generation.

        """
        assert vault.Vault.create_hash(
            phrase=phrases[0], service=service
        ) != vault.Vault.create_hash(phrase=phrases[1], service=service)

    @hypothesis.given(
        phrase=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=32,
        ),
        services=strategies.lists(
            strategies.binary(min_size=1, max_size=32),
            min_size=2,
            max_size=2,
            unique=True,
        ),
    )
    def test_101_create_hash_service_name_dependence(
        self,
        phrase: str,
        services: list[bytes],
    ) -> None:
        """The internal hash is dependent on the service name."""
        assert vault.Vault.create_hash(
            phrase=phrase, service=services[0]
        ) != vault.Vault.create_hash(phrase=phrase, service=services[1])

    @hypothesis.given(
        phrases=strategies.binary(max_size=BLOCK_SIZE // 2).flatmap(
            lambda bs: strategies.tuples(
                strategies.just(bs),
                strategies.integers(
                    min_value=1,
                    max_value=BLOCK_SIZE - len(bs),
                ).map(lambda num: bs + b'\x00' * num),
            )
        ),
        service=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=32,
        ),
    )
    def test_102a_interchangable_phrases_small(
        self,
        phrases: tuple[bytes, bytes],
        service: str,
    ) -> None:
        """Claimed interchangable passphrases are actually interchangable."""
        assert vault.Vault.phrases_are_interchangable(*phrases)
        assert vault.Vault.create_hash(
            phrase=phrases[0], service=service
        ) == vault.Vault.create_hash(phrase=phrases[1], service=service)

    @hypothesis.given(
        phrases=strategies.binary(
            min_size=BLOCK_SIZE + 1, max_size=BLOCK_SIZE + 8
        ).flatmap(
            lambda bs: strategies.tuples(
                strategies.just(bs),
                strategies.just(hashlib.sha1(bs).digest()).flatmap(
                    lambda h: strategies.integers(
                        min_value=1,
                        max_value=BLOCK_SIZE - DIGEST_SIZE,
                    ).map(lambda num: h + b'\x00' * num)
                ),
            )
        ),
        service=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=32,
        ),
    )
    def test_102b_interchangable_phrases_large(
        self,
        phrases: tuple[bytes, bytes],
        service: str,
    ) -> None:
        """Claimed interchangable passphrases are actually interchangable."""
        assert vault.Vault.phrases_are_interchangable(*phrases)
        assert vault.Vault.create_hash(
            phrase=phrases[0], service=service
        ) == vault.Vault.create_hash(phrase=phrases[1], service=service)

    @Parametrizations.SAMPLE_SERVICES_AND_PHRASES.value
    def test_200_basic_configuration(
        self, service: bytes | str, expected: bytes
    ) -> None:
        """Deriving a passphrase principally works."""
        assert vault.Vault(phrase=self.phrase).generate(service) == expected

    def test_201_phrase_dependence(self) -> None:
        """The derived passphrase is dependent on the master passphrase."""
        assert (
            vault.Vault(phrase=(self.phrase + b'X')).generate('google')
            == b'n+oIz6sL>K*lTEWYRO%7'
        )

    @hypothesis.given(
        phrases=strategies.lists(
            strategies.binary(min_size=1, max_size=32),
            min_size=2,
            max_size=2,
            unique=True,
        ).filter(lambda tup: not phrases_are_interchangable(*tup)),
        service=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=32,
        ),
    )
    @hypothesis.example(phrases=[b'\x00', b'\x00\x00'], service='0').xfail(
        reason='phrases are interchangable',
        raises=AssertionError,
    )
    @hypothesis.example(
        phrases=[
            (
                b'plnlrtfpijpuhqylxbgqiiyipieyxvfs'
                b'avzgxbbcfusqkozwpngsyejqlmjsytrmd'
            ),
            b"eBkXQTfuBqp'cTcar&g*",
        ],
        service='any service name here',
    ).xfail(
        reason=(
            'phrases are interchangable (Wikipedia example:'
            'https://en.wikipedia.org/w/index.php?title=PBKDF2&oldid=1264881215#HMAC_collisions'
            ')'
        ),
        raises=AssertionError,
    )
    def test_201a_phrase_dependence(
        self,
        phrases: list[bytes],
        service: str,
    ) -> None:
        """The derived passphrase is dependent on the master passphrase.

        Certain pairs of master passphrases are known to be
        interchangable; see [`vault.Vault.phrases_are_interchangable`][].
        These are excluded from consideration by the hypothesis
        strategy.

        """
        # See test_100_create_hash_phrase_dependence for context.
        assert vault.Vault(phrase=phrases[0]).generate(service) != vault.Vault(
            phrase=phrases[1]
        ).generate(service)

    def test_202a_reproducibility_and_bytes_service_name(self) -> None:
        """Deriving a passphrase works equally for byte strings."""
        assert vault.Vault(phrase=self.phrase).generate(
            b'google'
        ) == vault.Vault(phrase=self.phrase).generate('google')

    def test_202b_reproducibility_and_bytearray_service_name(self) -> None:
        """Deriving a passphrase works equally for byte arrays."""
        assert vault.Vault(phrase=self.phrase).generate(
            b'google'
        ) == vault.Vault(phrase=self.phrase).generate(bytearray(b'google'))

    def test_202c_reproducibility_and_buffer_like_service_name(self) -> None:
        """Deriving a passphrase works equally for memory views."""
        assert vault.Vault(phrase=self.phrase).generate(
            b'google'
        ) == vault.Vault(phrase=self.phrase).generate(memoryview(b'google'))

    @hypothesis.given(
        phrase=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=32,
        ),
        service=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=32,
        ),
    )
    def test_203a_reproducibility_and_binary_phrases(
        self,
        phrase: str,
        service: str,
    ) -> None:
        """Binary and text master passphrases generate the same passphrases."""
        buffer_types: dict[str, Callable[..., Buffer]] = {
            'bytes': bytes,
            'bytearray': bytearray,
            'memoryview': memoryview,
            'array.array': lambda data: array.array('B', data),
        }
        for type_name, buffer_type in buffer_types.items():
            str_phrase = phrase
            bytes_phrase = phrase.encode('utf-8')
            assert vault.Vault(phrase=str_phrase).generate(
                service
            ) == vault.Vault(phrase=buffer_type(bytes_phrase)).generate(
                service
            ), (
                f'{str_phrase!r} and {type_name}({bytes_phrase!r}) '
                'master passphrases generate different passphrases'
            )

    @hypothesis.given(
        phrase=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=32,
        ),
        service=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=32,
        ),
    )
    def test_203b_reproducibility_and_binary_service_name(
        self,
        phrase: str,
        service: str,
    ) -> None:
        """Binary and text service names generate the same passphrases."""
        buffer_types: dict[str, Callable[..., Buffer]] = {
            'bytes': bytes,
            'bytearray': bytearray,
            'memoryview': memoryview,
            'array.array': lambda data: array.array('B', data),
        }
        for type_name, buffer_type in buffer_types.items():
            str_service = service
            bytes_service = service.encode('utf-8')
            assert vault.Vault(phrase=phrase).generate(
                str_service
            ) == vault.Vault(phrase=phrase).generate(
                buffer_type(bytes_service)
            ), (
                f'{str_service!r} and {type_name}({bytes_service!r}) '
                'service name generate different passphrases'
            )

    @hypothesis.given(
        phrase=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=32,
        ),
        services=strategies.lists(
            strategies.binary(min_size=1, max_size=32),
            min_size=2,
            max_size=2,
            unique=True,
        ),
    )
    def test_204a_service_name_dependence(
        self,
        phrase: str,
        services: list[bytes],
    ) -> None:
        """The derived passphrase is dependent on the service name."""
        assert vault.Vault(phrase=phrase).generate(services[0]) != vault.Vault(
            phrase=phrase
        ).generate(services[1])

    @hypothesis.given(
        phrase=strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=32,
        ),
        config=tests.vault_full_service_config(),
        services=strategies.lists(
            strategies.binary(min_size=1, max_size=32),
            min_size=2,
            max_size=2,
            unique=True,
        ),
    )
    def test_204b_service_name_dependence_with_config(
        self,
        phrase: str,
        config: dict[str, int],
        services: list[bytes],
    ) -> None:
        """The derived passphrase is dependent on the service name."""
        try:
            assert vault.Vault(phrase=phrase, **config).generate(
                services[0]
            ) != vault.Vault(phrase=phrase, **config).generate(services[1])
        except ValueError as exc:  # pragma: no cover
            # The service configuration strategy attempts to only
            # generate satisfiable configurations.  It is possible,
            # though rare, that this fails, and that unsatisfiability is
            # only recognized when actually deriving a passphrase.  In
            # that case, reject the generated configuration.
            hypothesis.assume('no allowed characters left' not in exc.args)
            # Otherwise it's a genuine bug in the test case or the
            # implementation, and should be raised.
            raise

    def test_210_nonstandard_length(self) -> None:
        """Deriving a passphrase adheres to imposed length limits."""
        assert (
            vault.Vault(phrase=self.phrase, length=4).generate('google')
            == b'xDFu'
        )

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
    def test_210a_password_with_length(
        self,
        phrase: str | bytes,
        length: int,
        service: str,
    ) -> None:
        """Derived passphrases have the requested length."""
        password = vault.Vault(phrase=phrase, length=length).generate(service)
        assert len(password) == length

    def test_211_repetition_limit(self) -> None:
        """Deriving a passphrase adheres to imposed repetition limits."""
        assert (
            vault.Vault(
                phrase=b'', length=24, symbol=0, number=0, repeat=1
            ).generate('asd')
            == b'IVTDzACftqopUXqDHPkuCIhV'
        )

    def test_212_without_symbols(self) -> None:
        """Deriving a passphrase adheres to imposed limits on symbols."""
        assert (
            vault.Vault(phrase=self.phrase, symbol=0).generate('google')
            == b'XZ4wRe0bZCazbljCaMqR'
        )

    def test_213_no_numbers(self) -> None:
        """Deriving a passphrase adheres to imposed limits on numbers."""
        assert (
            vault.Vault(phrase=self.phrase, number=0).generate('google')
            == b'_*$TVH.%^aZl(LUeOT?>'
        )

    def test_214_no_lowercase_letters(self) -> None:
        """
        Deriving a passphrase adheres to imposed limits on lowercase letters.
        """
        assert (
            vault.Vault(phrase=self.phrase, lower=0).generate('google')
            == b':{?)+7~@OA:L]!0E$)(+'
        )

    def test_215_at_least_5_digits(self) -> None:
        """Deriving a passphrase adheres to imposed counts of numbers."""
        assert (
            vault.Vault(phrase=self.phrase, length=8, number=5).generate(
                'songkick'
            )
            == b'i0908.7['
        )

    def test_216_lots_of_spaces(self) -> None:
        """Deriving a passphrase adheres to imposed counts of spaces."""
        assert (
            vault.Vault(phrase=self.phrase, space=12).generate('songkick')
            == b' c   6 Bq  % 5fR    '
        )

    def test_217_all_character_classes(self) -> None:
        """Deriving a passphrase adheres to imposed counts of all types."""
        assert (
            vault.Vault(
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

    @hypothesis.given(
        phrase=strategies.one_of(
            strategies.binary(min_size=1), strategies.text(min_size=1)
        ),
        config=tests.vault_full_service_config(),
        service=strategies.text(min_size=1),
    )
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
    ).via('regression test')
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
    ).via('regression test')
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
    ).via('branch coverage (test function): "no repeats" case')
    def test_217a_all_length_character_and_occurrence_constraints_satisfied(
        self,
        phrase: str | bytes,
        config: dict[str, int],
        service: str,
    ) -> None:
        """Derived passphrases obey character and occurrence restraints."""
        try:
            password = vault.Vault(phrase=phrase, **config).generate(service)
        except ValueError as exc:  # pragma: no cover
            # The service configuration strategy attempts to only
            # generate satisfiable configurations.  It is possible,
            # though rare, that this fails, and that unsatisfiability is
            # only recognized when actually deriving a passphrase.  In
            # that case, reject the generated configuration.
            hypothesis.assume('no allowed characters left' not in exc.args)
            # Otherwise it's a genuine bug in the test case or the
            # implementation, and should be raised.
            raise
        n = len(password)
        assert n == config['length'], 'Password has wrong length.'
        for key in ('lower', 'upper', 'number', 'space', 'dash', 'symbol'):
            if config[key] > 0:
                assert (
                    sum(c in vault.Vault.CHARSETS[key] for c in password)
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
                    sum(c in vault.Vault.CHARSETS[key] for c in password) == 0
                ), 'Password does not satisfy character ban constraints.'

        T = TypeVar('T', str, bytes)

        def length_r_substrings(string: T, *, r: int) -> Iterator[T]:
            for i in range(len(string) - (r - 1)):
                yield string[i : i + r]

        repeat = config['repeat']
        if repeat:
            for snippet in length_r_substrings(password, r=(repeat + 1)):
                assert len(set(snippet)) > 1, (
                    'Password does not satisfy character repeat constraints.'
                )

    def test_218_only_numbers_and_very_high_repetition_limit(self) -> None:
        """Deriving a passphrase adheres to imposed repetition limits.

        This example is checked explicitly against forbidden substrings.

        """
        generated = vault.Vault(
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
    def test_218a_arbitrary_repetition_limit(
        self,
        phrase: str | bytes,
        length: int,
        repeat: int,
        service: str,
    ) -> None:
        """Derived passphrases obey the given occurrence constraint."""
        password = vault.Vault(
            phrase=phrase, length=length, repeat=repeat
        ).generate(service)
        for i in range((length + 1) - (repeat + 1)):
            assert len(set(password[i : i + repeat + 1])) > 1

    def test_219_very_limited_character_set(self) -> None:
        """Deriving a passphrase works even with limited character sets."""
        generated = vault.Vault(
            phrase=b'', length=24, lower=0, upper=0, space=0, symbol=0
        ).generate('testing')
        assert generated == b'763252593304946694588866'

    def test_220_character_set_subtraction(self) -> None:
        """Removing allowed characters internally works."""
        assert vault.Vault._subtract(b'be', b'abcdef') == bytearray(b'acdf')

    @Parametrizations.ENTROPY_RESULTS.value
    def test_221_entropy(
        self, length: int, settings: dict[str, int], entropy: int
    ) -> None:
        """Estimating the entropy and sufficient hash length works."""
        v = vault.Vault(length=length, **settings)  # type: ignore[arg-type]
        assert math.isclose(v._entropy(), entropy)
        assert v._estimate_sufficient_hash_length() > 0
        if math.isfinite(entropy) and entropy:
            assert v._estimate_sufficient_hash_length(1.0) == math.ceil(
                entropy / 8
            )
        assert v._estimate_sufficient_hash_length(8.0) >= entropy

    def test_222_hash_length_estimation(self) -> None:
        """
        Estimating the entropy and hash length for degenerate cases works.
        """
        v = vault.Vault(
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

    @Parametrizations.SAMPLE_SERVICES_AND_PHRASES.value
    def test_223_hash_length_expansion(
        self,
        monkeypatch: pytest.MonkeyPatch,
        service: str | bytes,
        expected: bytes,
    ) -> None:
        """
        Estimating the entropy and hash length for the degenerate case works.
        """
        v = vault.Vault(phrase=self.phrase)
        monkeypatch.setattr(
            v,
            '_estimate_sufficient_hash_length',
            lambda *args, **kwargs: 1,  # noqa: ARG005
        )
        assert v._estimate_sufficient_hash_length() < len(self.phrase)
        assert v.generate(service) == expected

    @Parametrizations.BINARY_STRINGS.value
    def test_224_binary_strings(self, s: str | bytes | bytearray) -> None:
        """Byte string conversion is idempotent."""
        binstr = vault.Vault._get_binary_string
        if isinstance(s, str):
            assert binstr(s) == s.encode('UTF-8')
            assert binstr(binstr(s)) == s.encode('UTF-8')
        else:
            assert binstr(s) == bytes(s)
            assert binstr(binstr(s)) == bytes(s)

    def test_310_too_many_symbols(self) -> None:
        """Deriving short passphrases with large length constraints fails."""
        with pytest.raises(
            ValueError, match='requested passphrase length too short'
        ):
            vault.Vault(phrase=self.phrase, symbol=100)

    def test_311_no_viable_characters(self) -> None:
        """Deriving passphrases without allowed characters fails."""
        with pytest.raises(ValueError, match='no allowed characters left'):
            vault.Vault(
                phrase=self.phrase,
                lower=0,
                upper=0,
                number=0,
                space=0,
                dash=0,
                symbol=0,
            )

    def test_320_character_set_subtraction_duplicate(self) -> None:
        """Character sets do not contain duplicate characters."""
        with pytest.raises(ValueError, match='duplicate characters'):
            vault.Vault._subtract(b'abcdef', b'aabbccddeeff')
        with pytest.raises(ValueError, match='duplicate characters'):
            vault.Vault._subtract(b'aabbccddeeff', b'abcdef')

    def test_322_hash_length_estimation(self) -> None:
        """Hash length estimation rejects invalid safety factors."""
        v = vault.Vault(phrase=self.phrase)
        with pytest.raises(ValueError, match='invalid safety factor'):
            assert v._estimate_sufficient_hash_length(-1.0)
        with pytest.raises(
            TypeError, match='invalid safety factor: not a float'
        ):
            assert v._estimate_sufficient_hash_length(None)  # type: ignore[arg-type]
