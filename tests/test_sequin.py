# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Test sequin.Sequin."""

import pytest

import sequin

import collections

benum = sequin.Sequin._big_endian_number

@pytest.mark.parametrize(['sequence', 'base', 'expected'], [
    ([1, 2, 3, 4, 5, 6], 10, 123456),
    ([1, 2, 3, 4, 5, 6], 100, 10203040506),
    ([0, 0, 1, 4, 9, 7], 10, 1497),
    ([1, 0, 0, 1, 0, 0, 0, 0], 2, 144),
    ([1, 7, 5, 5], 8, 0o1755),
])
def test_big_endian_number(sequence, base, expected):
    assert benum(sequence, base=base) == expected

@pytest.mark.parametrize(['exc_type', 'exc_pattern', 'sequence' , 'base'], [
    (ValueError, 'invalid base 3 digit:', [-1], 3),
    (ValueError, 'invalid base:', [0], 1),
])
def test_big_endian_number_exceptions(exc_type, exc_pattern, sequence, base):
    with pytest.raises(exc_type, match=exc_pattern):
        benum(sequence, base=base)

@pytest.mark.parametrize(['sequence', 'is_bitstring', 'expected'], [
    ([1, 0, 0, 1, 0, 1], False, [0, 0, 0, 0, 0, 0, 0, 1,
                                 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 1,
                                 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 1]),
    ([1, 0, 0, 1, 0, 1], True, [1, 0, 0, 1, 0, 1]),
    (b'OK', False, [0, 1, 0, 0, 1, 1, 1, 1,
                    0, 1, 0, 0, 1, 0, 1, 1]),
    ('OK', False, [0, 1, 0, 0, 1, 1, 1, 1,
                   0, 1, 0, 0, 1, 0, 1, 1]),
])
def test_constructor(sequence, is_bitstring, expected):
    seq = sequin.Sequin(sequence, is_bitstring=is_bitstring)
    assert seq.bases == {2: collections.deque(expected)}

@pytest.mark.parametrize(
    ['sequence', 'is_bitstring', 'exc_type', 'exc_pattern'],
    [
        ([0, 1, 2, 3, 4, 5, 6, 7], True,
         ValueError, 'sequence item out of range'),
        (u'こんにちは。', False,
         ValueError, 'sequence item out of range'),
    ]
)
def test_constructor_exceptions(sequence, is_bitstring, exc_type, exc_pattern):
    with pytest.raises(exc_type, match=exc_pattern):
        sequin.Sequin(sequence, is_bitstring=is_bitstring)

def test_shifting():
    seq = sequin.Sequin([1, 0, 1, 0, 0, 1, 0, 0, 0, 1], is_bitstring=True)
    assert seq.bases == {2: collections.deque([1, 0, 1, 0, 0, 1, 0, 0, 0, 1])}
    #
    assert seq._all_or_nothing_shift(3) == (1, 0, 1)
    assert seq._all_or_nothing_shift(3) == (0, 0, 1)
    assert seq.bases[2] == collections.deque([0, 0, 0, 1])
    #
    assert seq._all_or_nothing_shift(5) == ()
    assert seq.bases[2] == collections.deque([0, 0, 0, 1])
    #
    assert seq._all_or_nothing_shift(4), (0, 0, 0, 1)
    assert 2 not in seq.bases

def test_generating():
    seq = sequin.Sequin([1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1],
                        is_bitstring=True)
    assert seq.generate(1) == 0
    assert seq.generate(5) == 3
    assert seq.generate(5) == 3
    assert seq.generate(5) == 1
    with pytest.raises(sequin.SequinExhaustedException):
        seq.generate(5)
    with pytest.raises(sequin.SequinExhaustedException):
        seq.generate(1)
    seq = sequin.Sequin([1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1],
                        is_bitstring=True)
    with pytest.raises(ValueError, match='invalid target range'):
        seq.generate(0)

def test_internal_generating():
    seq = sequin.Sequin([1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1],
                        is_bitstring=True)
    assert seq._generate_inner(5) == 3
    assert seq._generate_inner(5) == 3
    assert seq._generate_inner(5) == 1
    assert seq._generate_inner(5) == 5
    assert seq._generate_inner(1) == 0
    seq = sequin.Sequin([1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1],
                        is_bitstring=True)
    assert seq._generate_inner(1) == 0
    with pytest.raises(ValueError, match='invalid target range'):
        seq._generate_inner(0)