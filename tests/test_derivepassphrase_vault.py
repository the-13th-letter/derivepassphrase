# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Test passphrase generation via derivepassphrase.vault.Vault."""

from __future__ import annotations

import array
import enum
import hashlib
import math
import types
from typing import TYPE_CHECKING

import hypothesis
import pytest
from hypothesis import strategies

from derivepassphrase import vault
from tests.machinery import hypothesis as hypothesis_machinery

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from typing_extensions import Buffer

BLOCK_SIZE = hashlib.sha1().block_size
DIGEST_SIZE = hashlib.sha1().digest_size

PHRASE = b"She cells C shells bye the sea shoars"
"""The standard passphrase from <i>vault</i>(1)'s test suite."""
GOOGLE_PHRASE = rb": 4TVH#5:aZl8LueOT\{"
"""
The standard derived passphrase for the "google" service, from
<i>vault</i>(1)'s test suite.
"""
TWITTER_PHRASE = rb"[ (HN_N:lI&<ro=)3'g9"
"""
The standard derived passphrase for the "twitter" service, from
<i>vault</i>(1)'s test suite.
"""

buffer_types: dict[str, Callable[..., Buffer]] = {
    "bytes": bytes,
    "bytearray": bytearray,
    "memoryview": memoryview,
    "array.array": lambda data: array.array("B", data),
}


class Parametrize(types.SimpleNamespace):
    ENTROPY_RESULTS = pytest.mark.parametrize(
        ["length", "settings", "entropy"],
        [
            (20, {}, math.log2(math.factorial(20)) + 20 * math.log2(94)),
            (
                20,
                {"upper": 0, "number": 0, "space": 0, "symbol": 0},
                math.log2(math.factorial(20)) + 20 * math.log2(26),
            ),
            (0, {}, float("-inf")),
            (
                0,
                {"lower": 0, "number": 0, "space": 0, "symbol": 0},
                float("-inf"),
            ),
            (1, {}, math.log2(94)),
            (1, {"upper": 0, "lower": 0, "number": 0, "symbol": 0}, 0.0),
        ],
    )
    MASTER_PASSPHRASE_TYPES = pytest.mark.parametrize(
        ["phrase1", "phrase2"],
        [(PHRASE.decode("UTF-8"), f(PHRASE)) for f in buffer_types.values()],
        ids=buffer_types.keys(),
    )
    BINARY_STRINGS = pytest.mark.parametrize(
        "s",
        [
            "ñ",
            "Düsseldorf",
            "liberté, egalité, fraternité",
            "ASCII",
            b"D\xc3\xbcsseldorf",
            bytearray([2, 3, 5, 7, 11, 13]),
        ],
    )
    SAMPLE_SERVICES_AND_PHRASES = pytest.mark.parametrize(
        ["service", "expected"],
        [
            (b"google", GOOGLE_PHRASE),
            ("twitter", TWITTER_PHRASE),
        ],
        ids=["google", "twitter"],
    )
    SERVICE_NAME_TYPES = pytest.mark.parametrize(
        ["sv1", "sv2"],
        [("email", f(b"email")) for f in buffer_types.values()],
        ids=buffer_types.keys(),
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
            hashlib.sha1(bs).digest() + b"\x00" * (BLOCK_SIZE - DIGEST_SIZE)
            if len(bs) > BLOCK_SIZE
            else bs.rstrip(b"\x00")
        )

    phrase1 = canon(vault.Vault._get_binary_string(phrase1))
    phrase2 = canon(vault.Vault._get_binary_string(phrase2))
    return phrase1 == phrase2


class PhraseSize(str, enum.Enum):
    """Size of the generated phrase.

    Attributes:
        SHORT: A phrase shorter than the SHA-1 block size.
        FULL: A phrase exactly as long as the SHA-1 block size.
        OVERLONG: A phrase longer than the SHA-1 block size.
        MIXED: A `SHORT`, `FULL` or `OVERLONG` phrase.

    """

    SHORT = enum.auto()
    """"""
    FULL = enum.auto()
    """"""
    OVERLONG = enum.auto()
    """"""
    MIXED = enum.auto()
    """"""


class Strategies:
    """Hypothesis strategies."""

    @staticmethod
    def text_strategy() -> strategies.SearchStrategy[str]:
        """Return a strategy for textual master passphrases or service names."""
        return strategies.text(
            strategies.characters(min_codepoint=32, max_codepoint=126),
            min_size=1,
            max_size=BLOCK_SIZE // 2,
        )

    @strategies.composite
    @staticmethod
    def binary_phrase_strategy(
        draw: strategies.DrawFn, size: PhraseSize = PhraseSize.MIXED
    ) -> Buffer:
        """Return a strategy for binary master passphrases.

        Args:
            draw:
                The [strategy drawing
                function][hypothesis.strategies.composite].
            size:
                The desired phrase size.

        Returns:
            The strategy.

        """
        if size == PhraseSize.MIXED:
            size = draw(
                strategies.sampled_from([
                    PhraseSize.SHORT,
                    PhraseSize.FULL,
                    PhraseSize.OVERLONG,
                ]),
                label="concrete_size",
            )
        min_size, max_size = (
            (1, BLOCK_SIZE // 2)
            if size == PhraseSize.SHORT
            else (BLOCK_SIZE, BLOCK_SIZE)
            if size == PhraseSize.FULL
            else (BLOCK_SIZE + 1, BLOCK_SIZE + 8)
        )
        return draw(
            strategies.binary(min_size=min_size, max_size=max_size),
            label="phrase",
        )

    @strategies.composite
    @staticmethod
    def pair_of_binary_phrases_strategy(
        draw: strategies.DrawFn, size: PhraseSize = PhraseSize.MIXED
    ) -> tuple[Buffer, Buffer]:
        """Return a strategy for two non-interchangable binary master passphrases.

        Args:
            draw:
                The [strategy drawing
                function][hypothesis.strategies.composite].
            size:
                The desired phrase size.

        Returns:
            The strategy.

        """
        phrase1 = draw(
            Strategies.binary_phrase_strategy(size=size), label="phrase1"
        )
        phrase2 = draw(
            Strategies.binary_phrase_strategy(size=size).filter(
                lambda p: not phrases_are_interchangable(phrase1, p)
            ),
            label="phrase2",
        )
        return (phrase1, phrase2)

    @strategies.composite
    @staticmethod
    def make_interchangable_phrases(
        draw: strategies.DrawFn, phrase: Buffer
    ) -> tuple[Buffer, Buffer]:
        """Transform a phrase into a pair of interchangable phrases.

        For phrases of size 64 (the SHA-1 block size), [in 99.6% of the
        cases][INTERCHANGABLE_PASSPHRASES], it is infeasible for us to
        find a second interchangable phrase.  (It would be equivalent to
        mounting a pre-image attack on an SHA-1, a cryptographically
        infeasible action.)  However, in the remaining 0.4% of cases,
        the phrase of size 64 is padded with NUL bytes at the end, and
        we can generate the second interchangable phrase by altering the
        padding.  For other phrase sizes, no such problems exist: we can
        obtain interchangable phrases by adding padding (if the phrase
        is shorter than 64 bytes) or by computing the SHA-1 value of the
        phrase (if it is longer than 64 bytes).

        [INTERCHANGABLE_PASSPHRASES]: https://the13thletter.info/derivepassphrase/0.x/explanation/faq-vault-interchangable-passphrases/ 'What are "interchangable passphrases" in `vault`, and what does that mean in practice?'

        Args:
            draw:
                The [strategy drawing
                function][hypothesis.strategies.composite].
            phrase:
                The first phrase.

        Returns:
            The strategy for two interchangable phrases.

        """
        p = bytes(phrase)
        hypothesis.assume(p.rstrip(b"\x00") != p or len(p) != BLOCK_SIZE)
        base = (
            hashlib.sha1(p).digest()
            if len(p) > BLOCK_SIZE
            else p.rstrip(b"\x00") or b"\x00"
        )
        zero_filled = [
            base + bytes(i)
            for i in range(BLOCK_SIZE - len(base) + 1)
            if base + bytes(i) != p
        ]
        return (p, draw(strategies.sampled_from(zero_filled)))


class TestVault:
    """Test passphrase derivation with the "vault" scheme."""

    phrase = PHRASE


class TestPhraseDependence:
    """Test the dependence of the internal hash on the master passphrase."""

    def _test(self, phrases: Sequence[bytes], service: str) -> None:
        assert vault.Vault.create_hash(
            phrase=phrases[0], service=service
        ) != vault.Vault.create_hash(phrase=phrases[1], service=service)

    @hypothesis.given(
        phrases=Strategies.pair_of_binary_phrases_strategy(
            size=PhraseSize.SHORT
        ),
        service=Strategies.text_strategy(),
    )
    @hypothesis.example(phrases=[b"\x00", b"\x00\x00"], service="0").xfail(
        reason="phrases are interchangable", raises=AssertionError
    )
    def test_small(self, phrases: Sequence[bytes], service: str) -> None:
        """The internal hash is dependent on the master passphrase.

        We filter out interchangable passphrases during generation.

        """
        self._test(phrases, service)

    @hypothesis.given(
        phrases=Strategies.pair_of_binary_phrases_strategy(
            size=PhraseSize.FULL
        ),
        service=Strategies.text_strategy(),
    )
    @hypothesis.example(
        phrases=[b"\x01" * DIGEST_SIZE, b"\x01" * DIGEST_SIZE],
        service="service",
    ).xfail(reason="phrases are interchangable", raises=AssertionError)
    def test_medium(self, phrases: Sequence[bytes], service: str) -> None:
        """The internal hash is dependent on the master passphrase.

        We filter out interchangable passphrases during generation.

        """
        self._test(phrases, service)

    @hypothesis.given(
        phrases=Strategies.pair_of_binary_phrases_strategy(
            size=PhraseSize.OVERLONG
        ),
        service=Strategies.text_strategy(),
    )
    def test_large(self, phrases: Sequence[bytes], service: str) -> None:
        """The internal hash is dependent on the master passphrase.

        We filter out interchangable passphrases during generation.

        """
        self._test(phrases, service)

    @hypothesis.given(
        phrases=Strategies.pair_of_binary_phrases_strategy(
            size=PhraseSize.MIXED
        ),
        service=Strategies.text_strategy(),
    )
    @hypothesis.example(
        phrases=[
            (
                b"plnlrtfpijpuhqylxbgqiiyipieyxvfs"
                b"avzgxbbcfusqkozwpngsyejqlmjsytrmd"
            ),
            b"eBkXQTfuBqp'cTcar&g*",
        ],
        service="any service name here",
    ).xfail(
        reason=(
            "phrases are interchangable (Wikipedia example:"
            "https://en.wikipedia.org/w/index.php?title=PBKDF2&oldid=1264881215#HMAC_collisions"
            ")"
        ),
        raises=AssertionError,
    )
    def test_mixed(self, phrases: Sequence[bytes], service: str) -> None:
        """The internal hash is dependent on the master passphrase.

        We filter out interchangable passphrases during generation.

        """
        self._test(phrases, service)


class TestServiceNameDependence:
    """Test the dependence of the internal hash on the service name."""

    @hypothesis.given(
        phrase=Strategies.text_strategy(),
        services=strategies.lists(
            Strategies.text_strategy(),
            min_size=2,
            max_size=2,
            unique=True,
        ),
    )
    def test_service_name_dependence(
        self,
        phrase: str,
        services: list[bytes],
    ) -> None:
        """The internal hash is dependent on the service name."""
        assert vault.Vault.create_hash(
            phrase=phrase, service=services[0]
        ) != vault.Vault.create_hash(phrase=phrase, service=services[1])


class TestInterchangablePhrases:
    """Test the interchangability of certain master passphrases."""

    def _test(self, phrases: Sequence[bytes], service: str) -> None:
        assert vault.Vault.phrases_are_interchangable(*phrases)
        assert vault.Vault.create_hash(
            phrase=phrases[0], service=service
        ) == vault.Vault.create_hash(phrase=phrases[1], service=service)

    @hypothesis.given(
        phrases=Strategies.binary_phrase_strategy(
            size=PhraseSize.SHORT
        ).flatmap(Strategies.make_interchangable_phrases),
        service=Strategies.text_strategy(),
    )
    def test_small(self, phrases: Sequence[bytes], service: str) -> None:
        """Claimed interchangable passphrases are actually interchangable."""
        self._test(phrases, service)

    @hypothesis.given(
        phrases=Strategies.binary_phrase_strategy(
            size=PhraseSize.OVERLONG,
        ).flatmap(Strategies.make_interchangable_phrases),
        service=Strategies.text_strategy(),
    )
    def test_large(self, phrases: Sequence[bytes], service: str) -> None:
        """Claimed interchangable passphrases are actually interchangable."""
        self._test(phrases, service)


class TestBasicFunctionalityFromUpstream(TestVault):
    """Test passphrase derivation with the "vault" scheme: upstream tests."""

    @Parametrize.SAMPLE_SERVICES_AND_PHRASES
    def test_basic_configuration(
        self, service: bytes | str, expected: bytes
    ) -> None:
        """Deriving a passphrase principally works."""
        assert vault.Vault(phrase=self.phrase).generate(service) == expected

    def test_phrase_dependence(self) -> None:
        """The derived passphrase is dependent on the master passphrase."""
        assert (
            vault.Vault(phrase=(self.phrase + b"X")).generate("google")
            == b"n+oIz6sL>K*lTEWYRO%7"
        )


class TestStringAndBinaryExchangability(TestVault):
    """Test the exchangability of text and byte strings in the "vault" scheme.

    This specifically refers to UTF-8-cleanliness, and buffer-type
    independence.

    """

    @Parametrize.SAMPLE_SERVICES_AND_PHRASES
    @Parametrize.MASTER_PASSPHRASE_TYPES
    def test_binary_phrases(
        self,
        phrase1: str,
        phrase2: Buffer,
        service: bytes | str,
        expected: bytes,
    ) -> None:
        """Binary and text master passphrases generate the same passphrases."""
        v1 = vault.Vault(phrase=phrase1)
        v2 = vault.Vault(phrase=phrase2)
        assert v1.generate(service) == expected
        assert v2.generate(service) == expected

    @Parametrize.SERVICE_NAME_TYPES
    def test_binary_service_name(self, sv1: str, sv2: Buffer) -> None:
        """Binary and text service names generate the same passphrases."""
        v = vault.Vault(phrase=self.phrase)
        assert v.generate(sv1) == v.generate(sv2)

    @hypothesis.given(
        phrase=Strategies.text_strategy(),
        service=Strategies.text_strategy(),
    )
    def test_binary_service_name_and_phrase(
        self,
        phrase: str,
        service: str,
    ) -> None:
        """Binary and text inputs generate the same passphrases."""
        v0 = vault.Vault(phrase=phrase)
        str_service = service
        result = v0.generate(str_service)
        bytes_service = service.encode("utf-8")

        for type_name, buffer_type in buffer_types.items():
            assert v0.generate(buffer_type(bytes_service)) == result, (
                f"mismatched result when using the {type_name} service name"
            )

        for type_name, buffer_type in buffer_types.items():
            v = vault.Vault(phrase=buffer_type(phrase.encode("utf-8")))
            assert v.generate(str_service) == result, (
                f"mismatched result when using the {type_name} "
                "master passphrase"
            )

        for type_name, buffer_type in buffer_types.items():
            v = vault.Vault(phrase=buffer_type(phrase.encode("utf-8")))
            for type_name2, buffer_type2 in buffer_types.items():
                assert v.generate(buffer_type2(bytes_service)) == result, (
                    f"mismatched result when using the {type_name} "
                    f"master passphrase and the {type_name2} service name"
                )


class TestConstraintSatisfactionFromUpstream(TestVault):
    """Test passphrase derivation with the "vault" scheme: upstream tests."""

    def test_nonstandard_length(self) -> None:
        """Deriving a passphrase adheres to imposed length limits."""
        assert (
            vault.Vault(phrase=self.phrase, length=4).generate("google")
            == b"xDFu"
        )

    def test_repetition_limit(self) -> None:
        """Deriving a passphrase adheres to imposed repetition limits."""
        assert (
            vault.Vault(
                phrase=b"", length=24, symbol=0, number=0, repeat=1
            ).generate("asd")
            == b"IVTDzACftqopUXqDHPkuCIhV"
        )

    def test_without_symbols(self) -> None:
        """Deriving a passphrase adheres to imposed limits on symbols."""
        assert (
            vault.Vault(phrase=self.phrase, symbol=0).generate("google")
            == b"XZ4wRe0bZCazbljCaMqR"
        )

    def test_no_numbers(self) -> None:
        """Deriving a passphrase adheres to imposed limits on numbers."""
        assert (
            vault.Vault(phrase=self.phrase, number=0).generate("google")
            == b"_*$TVH.%^aZl(LUeOT?>"
        )

    def test_no_lowercase_letters(self) -> None:
        """
        Deriving a passphrase adheres to imposed limits on lowercase letters.
        """
        assert (
            vault.Vault(phrase=self.phrase, lower=0).generate("google")
            == b":{?)+7~@OA:L]!0E$)(+"
        )

    def test_at_least_5_digits(self) -> None:
        """Deriving a passphrase adheres to imposed counts of numbers."""
        assert (
            vault.Vault(phrase=self.phrase, length=8, number=5).generate(
                "songkick"
            )
            == b"i0908.7["
        )

    def test_lots_of_spaces(self) -> None:
        """Deriving a passphrase adheres to imposed counts of spaces."""
        assert (
            vault.Vault(phrase=self.phrase, space=12).generate("songkick")
            == b" c   6 Bq  % 5fR    "
        )

    def test_all_character_classes(self) -> None:
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
            ).generate("google")
            == b": : fv_wqt>a-4w1S  R"
        )

    def test_only_numbers_and_very_high_repetition_limit(self) -> None:
        """Deriving a passphrase adheres to imposed repetition limits.

        This example is checked explicitly against forbidden substrings.

        """
        generated = vault.Vault(
            phrase=b"",
            length=40,
            lower=0,
            upper=0,
            space=0,
            dash=0,
            symbol=0,
            repeat=4,
        ).generate("abcdef")
        forbidden_substrings = {
            b"00000",
            b"11111",
            b"22222",
            b"33333",
            b"44444",
            b"55555",
            b"66666",
            b"77777",
            b"88888",
            b"99999",
        }
        for substring in forbidden_substrings:
            assert substring not in generated

    def test_very_limited_character_set(self) -> None:
        """Deriving a passphrase works even with limited character sets."""
        generated = vault.Vault(
            phrase=b"", length=24, lower=0, upper=0, space=0, symbol=0
        ).generate("testing")
        assert generated == b"763252593304946694588866"


class TestConstraintSatisfactionThoroughness(TestVault):
    """Test passphrase derivation with the "vault" scheme: constraint satisfaction."""

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
    def test_password_with_length(
        self,
        phrase: str | bytes,
        length: int,
        service: str,
    ) -> None:
        """Derived passphrases have the requested length."""
        password = vault.Vault(phrase=phrase, length=length).generate(service)
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
    def test_arbitrary_repetition_limit(
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
        last_char: str | int | None = None
        highest_count = 0
        count = 0
        for ch in password:
            if ch != last_char:
                last_char = ch
                count = 0
            else:
                count += 1
                highest_count = max(highest_count, count)
            assert count <= repeat


class TestConstraintSatisfactionHeavyDuty(TestVault):
    """Test passphrase derivation with the "vault" scheme: constraint satisfaction."""

    @hypothesis.given(
        phrase=strategies.one_of(
            strategies.binary(min_size=1), strategies.text(min_size=1)
        ),
        config=hypothesis_machinery.vault_full_service_config(),
        service=strategies.text(min_size=1),
    )
    @hypothesis.example(
        phrase=b"\x00",
        config={
            "lower": 0,
            "upper": 0,
            "number": 0,
            "space": 2,
            "dash": 0,
            "symbol": 1,
            "repeat": 2,
            "length": 3,
        },
        service="0",
    ).via("regression test")
    @hypothesis.example(
        phrase=b"\x00",
        config={
            "lower": 0,
            "upper": 0,
            "number": 0,
            "space": 1,
            "dash": 0,
            "symbol": 0,
            "repeat": 9,
            "length": 5,
        },
        service="0",
    ).via("regression test")
    @hypothesis.example(
        phrase=b"\x00",
        config={
            "lower": 0,
            "upper": 0,
            "number": 0,
            "space": 1,
            "dash": 0,
            "symbol": 0,
            "repeat": 0,
            "length": 5,
        },
        service="0",
    ).via('branch coverage (test function): "no repeats" case')
    def test_all_length_character_and_occurrence_constraints_satisfied(
        self,
        phrase: str | bytes,
        config: dict[str, int],
        service: str,
    ) -> None:
        """Derived passphrases obey character and occurrence constraints."""
        try:
            password = vault.Vault(phrase=phrase, **config).generate(service)
        except ValueError as exc:  # pragma: no cover
            # The service configuration strategy attempts to only
            # generate satisfiable configurations.  It is possible,
            # though rare, that this fails, and that unsatisfiability is
            # only recognized when actually deriving a passphrase.  In
            # that case, reject the generated configuration.
            hypothesis.assume("no allowed characters left" not in exc.args)
            # Otherwise it's a genuine bug in the test case or the
            # implementation, and should be raised.
            raise
        n = len(password)
        assert n == config["length"], "Password has wrong length."
        for key in ("lower", "upper", "number", "space", "dash", "symbol"):
            if config[key] > 0:
                assert (
                    sum(c in vault.Vault.CHARSETS[key] for c in password)
                    >= config[key]
                ), (
                    "Password does not satisfy "
                    "character occurrence constraints."
                )
            elif key in {"dash", "symbol"}:
                # Character classes overlap, so "forbidden" characters may
                # appear via the other character class.
                assert True
            else:
                assert (
                    sum(c in vault.Vault.CHARSETS[key] for c in password) == 0
                ), "Password does not satisfy character ban constraints."

        repeat = config["repeat"]
        if repeat:
            last_char: str | int | None = None
            highest_count = 0
            count = 0
            for ch in password:
                if ch != last_char:
                    last_char = ch
                    count = 0
                else:
                    count += 1
                    highest_count = max(highest_count, count)
                assert count <= repeat, (
                    "Password does not satisfy character repeat constraints."
                )


class TestUtilities(TestVault):
    """Test passphrase derivation with the "vault" scheme: utility tests."""

    def test_character_set_subtraction(self) -> None:
        """Removing allowed characters internally works."""
        assert vault.Vault._subtract(b"be", b"abcdef") == bytearray(b"acdf")

    @Parametrize.ENTROPY_RESULTS
    def test_entropy(
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

    def test_hash_length_estimation(self) -> None:
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
        assert v._entropy() == 0.0  # noqa: RUF069
        assert v._estimate_sufficient_hash_length() > 0

    @Parametrize.SAMPLE_SERVICES_AND_PHRASES
    def test_hash_length_expansion(
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
            "_estimate_sufficient_hash_length",
            lambda *_args, **_kwargs: 1,
        )
        assert v._estimate_sufficient_hash_length() < len(self.phrase)
        assert v.generate(service) == expected

    @Parametrize.BINARY_STRINGS
    def test_binary_strings(self, s: str | bytes | bytearray) -> None:
        """Byte string conversion is idempotent."""
        binstr = vault.Vault._get_binary_string
        if isinstance(s, str):
            assert binstr(s) == s.encode("UTF-8")
            assert binstr(binstr(s)) == s.encode("UTF-8")
        else:
            assert binstr(s) == bytes(s)
            assert binstr(binstr(s)) == bytes(s)

    def test_too_many_symbols(self) -> None:
        """Deriving short passphrases with large length constraints fails."""
        with pytest.raises(
            ValueError, match="requested passphrase length too short"
        ):
            vault.Vault(phrase=self.phrase, symbol=100)

    def test_no_viable_characters(self) -> None:
        """Deriving passphrases without allowed characters fails."""
        with pytest.raises(ValueError, match="no allowed characters left"):
            vault.Vault(
                phrase=self.phrase,
                lower=0,
                upper=0,
                number=0,
                space=0,
                dash=0,
                symbol=0,
            )

    def test_character_set_subtraction_duplicate(self) -> None:
        """Character sets do not contain duplicate characters."""
        with pytest.raises(ValueError, match="duplicate characters"):
            vault.Vault._subtract(b"abcdef", b"aabbccddeeff")
        with pytest.raises(ValueError, match="duplicate characters"):
            vault.Vault._subtract(b"aabbccddeeff", b"abcdef")

    def test_invalid_hash_length_estimation_safety_factor(self) -> None:
        """Hash length estimation rejects invalid safety factors."""
        v = vault.Vault(phrase=self.phrase)
        with pytest.raises(ValueError, match="invalid safety factor"):
            assert v._estimate_sufficient_hash_length(-1.0)
        with pytest.raises(
            TypeError, match="invalid safety factor: not a float"
        ):
            assert v._estimate_sufficient_hash_length(None)  # type: ignore[arg-type]
