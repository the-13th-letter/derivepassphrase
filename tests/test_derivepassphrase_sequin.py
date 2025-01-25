# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Test sequin.Sequin."""

from __future__ import annotations

import collections
import contextlib
import functools
import math
import operator
from typing import TYPE_CHECKING, NamedTuple

import hypothesis
import pytest
from hypothesis import strategies

from derivepassphrase import sequin

if TYPE_CHECKING:
    from collections.abc import Sequence


def bits(num: int, /, byte_width: int | None = None) -> list[int]:
    """Return the list of bits of an integer, in big endian order.

    Args:
        num:
            The number whose bits are to be returned.
        byte_width:
            Pad the returned list of bits to the given byte width if given,
            else its natural byte width.

    """
    if num < 0:  # pragma: no cover
        err_msg = 'Negative numbers are unsupported'
        raise NotImplementedError(err_msg)
    if byte_width is None:
        byte_width = math.ceil(math.log2(num) / 8) if num else 1
    seq: list[int] = []
    while num:
        seq.append(num % 2)
        num >>= 1
    seq.reverse()
    missing_bit_count = 8 * byte_width - len(seq)
    seq[:0] = [0] * missing_bit_count
    return seq


def bitseq(string: str) -> list[int]:
    """Convert a 0/1-string into a list of bits."""
    return [int(char, 2) for char in string]


class TestStaticFunctionality:
    """Test the static functionality in the `sequin` module."""

    @hypothesis.given(
        num=strategies.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    )
    def test_100_bits(self, num: int) -> None:
        """Extract the bits from a number in big-endian format."""
        seq1 = bits(num)
        n = len(seq1)
        seq2 = bits(num, byte_width=8)
        m = len(seq2)
        assert m == 64
        assert seq2[-n:] == seq1
        assert seq2[: m - n] == [0] * (m - n)
        text1 = ''.join(str(bit) for bit in seq1)
        text2 = ''.join(str(bit) for bit in seq2)
        assert text1.lstrip('0') == (f'{num:b}' if num else '')
        assert text2 == f'{num:064b}'

    @hypothesis.given(
        num=strategies.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    )
    def test_101_bits(self, num: int) -> None:
        """Extract the bits from a number in big-endian format."""
        text1 = f'{num:064b}'
        seq1 = bitseq(text1)
        seq2 = bits(num, byte_width=8)
        assert seq1 == seq2
        text2 = ''.join(str(bit) for bit in seq1)
        assert int(text2, 2) == num

    class BigEndianNumberTest(NamedTuple):
        """Test data for
        [`TestStaticFunctionality.test_200_big_endian_number`][].

        Attributes:
            sequence: A sequence of integers.
            base: The numeric base.
            expected: The expected result.

        """

        sequence: list[int]
        """"""
        base: int
        """"""
        expected: int
        """"""

        @strategies.composite
        @staticmethod
        def strategy(
            draw: strategies.DrawFn,
            *,
            base: int | None = None,
            max_size: int | None = None,
        ) -> TestStaticFunctionality.BigEndianNumberTest:
            """Return a sample BigEndianNumberTest.

            Args:
                draw:
                    The `draw` function, as provided for by hypothesis.
                base:
                    The numeric base, an integer between 2 and 65536 (inclusive).
                max_size:
                    The maximum size of the sequence, up to 128.

            Raises:
                AssertionError:
                    `base` or `max_size` are invalid.

            """
            if base is None:  # pragma: no cover
                base = 256
            assert isinstance(base, int)
            assert base in range(2, 65537)
            if max_size is None:  # pragma: no cover
                max_size = 128
            assert isinstance(max_size, int)
            assert max_size in range(129)
            sequence = draw(
                strategies.lists(
                    strategies.integers(min_value=0, max_value=(base - 1)),
                    max_size=max_size,
                ),
            )
            value = functools.reduce(lambda x, y: x * base + y, sequence, 0)
            return TestStaticFunctionality.BigEndianNumberTest(
                sequence, base, value
            )

    @hypothesis.given(test_case=BigEndianNumberTest.strategy())
    @hypothesis.example(
        BigEndianNumberTest([1, 2, 3, 4, 5, 6], 10, 123456)
    ).via('manual decimal example')
    @hypothesis.example(
        BigEndianNumberTest([1, 2, 3, 4, 5, 6], 100, 10203040506)
    ).via('manual decimal example in different base')
    @hypothesis.example(BigEndianNumberTest([0, 0, 1, 4, 9, 7], 10, 1497)).via(
        'manual example with leading zeroes'
    )
    @hypothesis.example(
        BigEndianNumberTest([1, 0, 0, 1, 0, 0, 0, 0], 2, 144)
    ).via('manual binary example')
    @hypothesis.example(BigEndianNumberTest([1, 7, 5, 5], 8, 0o1755)).via(
        'manual octal example'
    )
    def test_200_big_endian_number(
        self, test_case: BigEndianNumberTest
    ) -> None:
        """Conversion to big endian numbers in any base works.

        See [`sequin.Sequin.generate`][] for where this is used.

        """
        sequence, base, expected = test_case
        assert (
            sequin.Sequin._big_endian_number(sequence, base=base)
        ) == expected

    @pytest.mark.parametrize(
        ['exc_type', 'exc_pattern', 'sequence', 'base'],
        [
            (ValueError, 'invalid base 3 digit:', [-1], 3),
            (ValueError, 'invalid base:', [0], 1),
            (TypeError, 'not an integer:', [0.0, 1.0, 0.0, 1.0], 2),
        ],
    )
    def test_300_big_endian_number_exceptions(
        self,
        exc_type: type[Exception],
        exc_pattern: str,
        sequence: list[int],
        base: int,
    ) -> None:
        """Nonsensical conversion of numbers in a given base raises.

        See [`sequin.Sequin.generate`][] for where this is used.

        """
        with pytest.raises(exc_type, match=exc_pattern):
            sequin.Sequin._big_endian_number(sequence, base=base)


class TestSequin:
    """Test the `Sequin` class."""

    class ConstructorTestCase(NamedTuple):
        """A test case for the constructor.

        Attributes:
            sequence:
                A sequence of ints, bits, or Latin1 characters.
            is_bitstring:
                True if and only if `sequence` denotes bits.
            expected:
                The expected bit sequence of the internal entropy pool.

        """

        sequence: Sequence[int] | str
        """"""
        is_bitstring: bool
        """"""
        expected: Sequence[int]

        @strategies.composite
        @staticmethod
        def strategy(
            draw: strategies.DrawFn,
            *,
            max_entropy: int | None = None,
        ) -> TestSequin.ConstructorTestCase:
            """Return a constructor test case.

            Args:
                max_entropy:
                    The maximum entropy, in bits.  Must be between 0 and
                    256, inclusive.

            Raises:
                AssertionError:
                    `max_entropy` is invalid.

            """
            if max_entropy is None:  # pragma: no branch
                max_entropy = 256
            assert max_entropy in range(257)
            is_bytecount = max_entropy % 8 == 0
            is_bitstring = (
                draw(strategies.randoms()).choice([False, True])
                if is_bytecount
                else True
            )
            sequence: Sequence[int] | str
            expected: Sequence[int]
            if is_bitstring:
                sequence = draw(
                    strategies.lists(
                        strategies.integers(min_value=0, max_value=1),
                        max_size=max_entropy,
                    )
                )
                expected = sequence
            else:
                bytecount = max_entropy // 8
                raw_sequence = draw(strategies.binary(max_size=bytecount))
                sequence_format = draw(strategies.randoms()).choice([
                    'bytes',
                    'ints',
                    'text',
                ])
                if sequence_format == 'bytes':
                    sequence = raw_sequence
                elif sequence_format == 'ints':
                    sequence = list(raw_sequence)
                else:
                    sequence = raw_sequence.decode('latin1')
                bytestring = (
                    sequence.encode('latin1')
                    if isinstance(sequence, str)
                    else bytes(sequence)
                )
                expected = []
                for byte in bytestring:
                    expected.extend(bits(byte, byte_width=1))
            return TestSequin.ConstructorTestCase(
                sequence, is_bitstring, expected
            )

    @hypothesis.given(test_case=ConstructorTestCase.strategy())
    @hypothesis.example(
        ConstructorTestCase([1, 0, 0, 1, 0, 1], True, [1, 0, 0, 1, 0, 1])
    ).via('manual example bitstring')
    @hypothesis.example(
        ConstructorTestCase(
            [1, 0, 0, 1, 0, 1],
            False,
            bitseq('000000010000000000000000000000010000000000000001'),
        )
    ).via('manual example bitstring as byte string')
    @hypothesis.example(
        ConstructorTestCase(b'OK', False, bitseq('0100111101001011'))
    ).via('manual example true byte string')
    @hypothesis.example(
        ConstructorTestCase('OK', False, bitseq('0100111101001011'))
    ).via('manual example latin1 text')
    def test_200_constructor(
        self,
        test_case: ConstructorTestCase,
    ) -> None:
        """The constructor handles both bit and integer sequences."""
        sequence, is_bitstring, expected = test_case
        seq = sequin.Sequin(sequence, is_bitstring=is_bitstring)
        assert seq.bases == {2: collections.deque(expected)}

    class GenerationSequence(NamedTuple):
        """A sequence of generation results.

        Attributes:
            bit_sequence:
                The input bit sequence.
            steps:
                A sequence of generation steps.  Each step details
                a requested number base, and the respective result (a
                number, or [`sequin.SequinExhaustedError`][]).

        """

        bit_sequence: Sequence[int]
        """"""
        steps: Sequence[tuple[int, int | type[sequin.SequinExhaustedError]]]
        """"""

        @strategies.composite
        @staticmethod
        def strategy(draw: strategies.DrawFn) -> TestSequin.GenerationSequence:
            """Return a generation sequence."""
            # Signal that there is only one value.
            draw(strategies.just(None))
            return TestSequin.GenerationSequence(
                bitseq('110101011111001'),
                [
                    (1, 0),
                    (5, 3),
                    (5, 3),
                    (5, 1),
                    (5, sequin.SequinExhaustedError),
                    (1, sequin.SequinExhaustedError),
                ],
            )

    @hypothesis.example(
        GenerationSequence(
            bitseq('110101011111001'),
            [
                (1, 0),
                (5, 3),
                (5, 3),
                (5, 1),
                (5, sequin.SequinExhaustedError),
                (1, sequin.SequinExhaustedError),
            ],
        )
    ).via('manual, pre-hypothesis parametrization value')
    @hypothesis.given(sequence=GenerationSequence.strategy())
    def test_201_generating(self, sequence: GenerationSequence) -> None:
        """The sequin generates deterministic sequences."""
        seq = sequin.Sequin(sequence.bit_sequence, is_bitstring=True)
        for i, (num, result) in enumerate(sequence.steps, start=1):
            if isinstance(result, int):
                assert seq.generate(num) == result, (
                    f'Failed to generate {result:d} in step {i}'
                )
            else:
                # Can't use pytest.raises here, because the assertion error
                # message is not customizable and we would lose information
                # about which step we're executing.
                with contextlib.suppress(sequin.SequinExhaustedError):
                    result2 = seq.generate(num)
                    pytest.fail(
                        f'Expected to be exhausted in step {i}, '
                        f'but generated {result2:d} instead'
                    )

    def test_201a_generating_errors(self) -> None:
        """The sequin errors deterministically when generating sequences."""
        seq = sequin.Sequin(
            [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1], is_bitstring=True
        )
        with pytest.raises(ValueError, match='invalid target range'):
            seq.generate(0)

    @hypothesis.example(
        GenerationSequence(
            bitseq('110101011111001'),
            [
                (1, 0),
                (5, 3),
                (5, 3),
                (5, 1),
                (5, sequin.SequinExhaustedError),
                (1, sequin.SequinExhaustedError),
            ],
        )
    ).via('manual, pre-hypothesis parametrization value')
    @hypothesis.given(sequence=GenerationSequence.strategy())
    def test_210_internal_generating(
        self, sequence: GenerationSequence
    ) -> None:
        """The sequin internals generate deterministic sequences."""
        seq = sequin.Sequin(sequence.bit_sequence, is_bitstring=True)
        for i, (num, result) in enumerate(sequence.steps, start=1):
            if num == 1:
                assert seq._generate_inner(num) == 0, (
                    f'Failed to generate {result:d} in step {i}'
                )
            elif isinstance(result, int):
                assert seq._generate_inner(num) == result, (
                    f'Failed to generate {result:d} in step {i}'
                )
            else:
                result2 = seq._generate_inner(num)
                assert result2 == num, (
                    f'Expected to be exhausted in step {i}, '
                    f'but generated {result2:d} instead'
                )

    def test_210a_internal_generating_errors(self) -> None:
        """The sequin generation internals error deterministically."""
        seq = sequin.Sequin(
            [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1], is_bitstring=True
        )
        with pytest.raises(ValueError, match='invalid target range'):
            seq._generate_inner(0)
        with pytest.raises(ValueError, match='invalid base:'):
            seq._generate_inner(16, base=1)

    class ShiftSequence(NamedTuple):
        """A sequence of bit sequence shift operations.

        Attributes:
            bit_sequence:
                The input bit sequence.
            steps:
                A sequence of shift steps.  Each step details
                a requested shift size, the respective result, and the
                bit sequence status afterward.

        """

        bit_sequence: Sequence[int]
        """"""
        steps: Sequence[tuple[int, Sequence[int], Sequence[int]]]
        """"""

        @strategies.composite
        @staticmethod
        def strategy(draw: strategies.DrawFn) -> TestSequin.ShiftSequence:
            """Return a generation sequence."""
            no_op_counts_strategy = strategies.lists(
                strategies.integers(min_value=0, max_value=0),
                min_size=3,
                max_size=3,
            )
            true_counts_strategy = strategies.lists(
                strategies.integers(min_value=1, max_value=5),
                min_size=3,
                max_size=10,
            ).map(sorted)
            bits_strategy = strategies.integers(min_value=0, max_value=1)
            counts = draw(
                strategies.builds(
                    operator.add,
                    no_op_counts_strategy,
                    true_counts_strategy,
                ).flatmap(strategies.permutations)
            )
            bit_sequence: list[int] = []
            steps: list[tuple[int, Sequence[int], list[int]]] = []
            for i, count in enumerate(counts):
                shift_result = draw(
                    strategies.lists(
                        bits_strategy, min_size=count, max_size=count
                    )
                )
                for step in steps[:i]:
                    step[2].extend(shift_result)
                bit_sequence.extend(shift_result)
                steps.append((count, shift_result, []))
            return TestSequin.ShiftSequence(bit_sequence, steps)

    @hypothesis.given(sequence=ShiftSequence.strategy())
    @hypothesis.example(
        ShiftSequence(
            bitseq('1010010001'),
            [
                (3, bitseq('101'), bitseq('0010001')),
                (3, bitseq('001'), bitseq('0001')),
                (5, bitseq(''), bitseq('0001')),
                (4, bitseq('0001'), bitseq('')),
            ],
        )
    )
    def test_211_shifting(self, sequence: ShiftSequence) -> None:
        """The sequin manages the pool of remaining entropy for each base.

        Specifically, the sequin implements all-or-nothing fixed-length
        draws from the entropy pool.

        """
        seq = sequin.Sequin(sequence.bit_sequence, is_bitstring=True)
        assert seq.bases == {2: collections.deque(sequence.bit_sequence)}
        for i, (count, result, remaining) in enumerate(
            sequence.steps, start=1
        ):
            actual_result = seq._all_or_nothing_shift(count)
            assert actual_result == tuple(result), (
                f'At step {i}, the shifting result differs'
            )
            if remaining:
                assert seq.bases[2] == collections.deque(remaining), (
                    f'After step {i}, the remaining bit sequence differs'
                )
            else:
                assert 2 not in seq.bases, (
                    f'After step {i}, the bit sequence is not exhausted yet'
                )

    @pytest.mark.parametrize(
        ['sequence', 'is_bitstring', 'exc_type', 'exc_pattern'],
        [
            (
                [0, 1, 2, 3, 4, 5, 6, 7],
                True,
                ValueError,
                'sequence item out of range',
            ),
            ('こんにちは。', False, ValueError, 'sequence item out of range'),
        ],
    )
    def test_300_constructor_exceptions(
        self,
        sequence: list[int] | str,
        is_bitstring: bool,
        exc_type: type[Exception],
        exc_pattern: str,
    ) -> None:
        """The sequin raises on invalid bit and integer sequences."""
        with pytest.raises(exc_type, match=exc_pattern):
            sequin.Sequin(sequence, is_bitstring=is_bitstring)
