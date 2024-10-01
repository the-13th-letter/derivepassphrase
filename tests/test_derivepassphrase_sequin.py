# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Test sequin.Sequin."""

from __future__ import annotations

import collections

import pytest

from derivepassphrase import sequin


def bitseq(string: str) -> list[int]:
    """Convert a 0/1-string into a list of bits."""
    return [int(char, 2) for char in string]


class TestStaticFunctionality:
    @pytest.mark.parametrize(
        ['sequence', 'base', 'expected'],
        [
            ([1, 2, 3, 4, 5, 6], 10, 123456),
            ([1, 2, 3, 4, 5, 6], 100, 10203040506),
            ([0, 0, 1, 4, 9, 7], 10, 1497),
            ([1, 0, 0, 1, 0, 0, 0, 0], 2, 144),
            ([1, 7, 5, 5], 8, 0o1755),
        ],
    )
    def test_200_big_endian_number(
        self, sequence: list[int], base: int, expected: int
    ) -> None:
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
        with pytest.raises(exc_type, match=exc_pattern):
            sequin.Sequin._big_endian_number(sequence, base=base)


class TestSequin:
    @pytest.mark.parametrize(
        ['sequence', 'is_bitstring', 'expected'],
        [
            (
                [1, 0, 0, 1, 0, 1],
                False,
                bitseq('000000010000000000000000000000010000000000000001'),
            ),
            ([1, 0, 0, 1, 0, 1], True, [1, 0, 0, 1, 0, 1]),
            (b'OK', False, bitseq('0100111101001011')),
            ('OK', False, bitseq('0100111101001011')),
        ],
    )
    def test_200_constructor(
        self,
        sequence: str | bytes | bytearray | list[int],
        is_bitstring: bool,
        expected: list[int],
    ) -> None:
        seq = sequin.Sequin(sequence, is_bitstring=is_bitstring)
        assert seq.bases == {2: collections.deque(expected)}

    def test_201_generating(self) -> None:
        seq = sequin.Sequin(
            [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1], is_bitstring=True
        )
        assert seq.generate(1) == 0
        assert seq.generate(5) == 3
        assert seq.generate(5) == 3
        assert seq.generate(5) == 1
        with pytest.raises(sequin.SequinExhaustedError):
            seq.generate(5)
        with pytest.raises(sequin.SequinExhaustedError):
            seq.generate(1)
        seq = sequin.Sequin(
            [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1], is_bitstring=True
        )
        with pytest.raises(ValueError, match='invalid target range'):
            seq.generate(0)

    def test_210_internal_generating(self) -> None:
        seq = sequin.Sequin(
            [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1], is_bitstring=True
        )
        assert seq._generate_inner(5) == 3
        assert seq._generate_inner(5) == 3
        assert seq._generate_inner(5) == 1
        assert seq._generate_inner(5) == 5
        assert seq._generate_inner(1) == 0
        seq = sequin.Sequin(
            [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1], is_bitstring=True
        )
        assert seq._generate_inner(1) == 0
        with pytest.raises(ValueError, match='invalid target range'):
            seq._generate_inner(0)
        with pytest.raises(ValueError, match='invalid base:'):
            seq._generate_inner(16, base=1)

    def test_211_shifting(self) -> None:
        seq = sequin.Sequin([1, 0, 1, 0, 0, 1, 0, 0, 0, 1], is_bitstring=True)
        assert seq.bases == {
            2: collections.deque([1, 0, 1, 0, 0, 1, 0, 0, 0, 1])
        }

        assert seq._all_or_nothing_shift(3) == (1, 0, 1)
        assert seq._all_or_nothing_shift(3) == (0, 0, 1)
        assert seq.bases[2] == collections.deque([0, 0, 0, 1])

        assert seq._all_or_nothing_shift(5) == ()
        assert seq.bases[2] == collections.deque([0, 0, 0, 1])

        assert seq._all_or_nothing_shift(4), (0, 0, 0, 1)
        assert 2 not in seq.bases

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
        with pytest.raises(exc_type, match=exc_pattern):
            sequin.Sequin(sequence, is_bitstring=is_bitstring)
