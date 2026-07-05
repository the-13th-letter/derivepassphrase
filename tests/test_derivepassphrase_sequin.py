# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Test sequin.Sequin."""

from __future__ import annotations

import collections
import contextlib
import functools
import math
import operator
import types
from typing import TYPE_CHECKING, NamedTuple

import hypothesis
import pytest
from hypothesis import stateful, strategies

from derivepassphrase import sequin
from tests.machinery import hypothesis as hypothesis_machinery
from tests.machinery import pytest as pytest_machinery

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
        err_msg = "Negative numbers are unsupported"
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


class Parametrize(types.SimpleNamespace):
    BIG_ENDIAN_NUMBER_EXCEPTIONS = hypothesis_machinery.explicit_examples(
        ["exc_type", "exc_pattern", "sequence", "base"],
        [
            (ValueError, "invalid base 3 digit:", [-1], 3),
            (ValueError, "invalid base:", [0], 1),
            (TypeError, "not an integer:", [0.0, 1.0, 0.0, 1.0], 2),
        ],
    )
    INVALID_SEQUIN_INPUTS = hypothesis_machinery.explicit_examples(
        ["sequence", "is_bitstring", "exc_type", "exc_pattern"],
        [
            (
                [0, 1, 2, 3, 4, 5, 6, 7],
                True,
                ValueError,
                "sequence item out of range",
            ),
            ("こんにちは。", False, ValueError, "sequence item out of range"),
        ],
    )


class TestStaticFunctionality:
    """Test the static functionality in the `sequin` module."""

    @hypothesis.given(
        num=strategies.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    )
    def test_bits(self, num: int) -> None:
        """Extract the bits from a number in big-endian format."""
        seq1 = bits(num)
        n = len(seq1)
        seq2 = bits(num, byte_width=8)
        m = len(seq2)
        text1 = "".join(str(bit) for bit in seq1)
        text2 = "".join(str(bit) for bit in seq2)
        text3 = f"{num:064b}"
        seq3 = bitseq(text3)
        assert m == 64
        assert seq2 == seq3
        assert seq2[-n:] == seq1
        assert seq2[: m - n] == [0] * (m - n)
        assert text1.lstrip("0") == (f"{num:b}" if num else "")
        assert text2.endswith(text1)
        assert int(text2, 2) == num
        assert text2 == text3

    class BigEndianNumberTest(NamedTuple):
        """Test data for
        [`TestStaticFunctionality.test_big_endian_number`][].

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
    # decimal example
    @hypothesis.example(
        test_case=BigEndianNumberTest([1, 2, 3, 4, 5, 6], 10, 123456)
    )
    # decimal example, different base
    @hypothesis.example(
        test_case=BigEndianNumberTest([1, 2, 3, 4, 5, 6], 100, 10203040506)
    )
    # leading zeroes example
    @hypothesis.example(
        test_case=BigEndianNumberTest([0, 0, 1, 4, 9, 7], 10, 1497)
    )
    # binary example
    @hypothesis.example(
        test_case=BigEndianNumberTest([1, 0, 0, 1, 0, 0, 0, 0], 2, 144)
    )
    # octal example
    @hypothesis.example(test_case=BigEndianNumberTest([1, 7, 5, 5], 8, 0o1755))
    def test_big_endian_number(self, test_case: BigEndianNumberTest) -> None:
        """Conversion to big endian numbers in any base works.

        See [`sequin.Sequin.generate`][] for where this is used.

        """
        sequence, base, expected = test_case
        assert (
            sequin.Sequin._big_endian_number(sequence, base=base)
        ) == expected

    @Parametrize.BIG_ENDIAN_NUMBER_EXCEPTIONS
    def test_big_endian_number_exceptions(
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
                    "bytes",
                    "ints",
                    "text",
                ])
                if sequence_format == "bytes":
                    sequence = raw_sequence
                elif sequence_format == "ints":
                    sequence = list(raw_sequence)
                else:
                    sequence = raw_sequence.decode("latin1")
                bytestring = (
                    sequence.encode("latin1")
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
    # bitstring example
    @hypothesis.example(
        test_case=ConstructorTestCase(
            [1, 0, 0, 1, 0, 1], True, [1, 0, 0, 1, 0, 1]
        )
    )
    # bitstring as bytestring example
    @hypothesis.example(
        test_case=ConstructorTestCase(
            [1, 0, 0, 1, 0, 1],
            False,
            bitseq("000000010000000000000000000000010000000000000001"),
        )
    )
    # true byte string example
    @hypothesis.example(
        test_case=ConstructorTestCase(b"OK", False, bitseq("0100111101001011"))
    )
    # latin1 text example
    @hypothesis.example(
        test_case=ConstructorTestCase("OK", False, bitseq("0100111101001011"))
    )
    def test_constructor(
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

        # TODO(the-13th-letter): Add more known sequences. Derive those
        # from sequin.js.
        @strategies.composite
        @staticmethod
        def strategy(draw: strategies.DrawFn) -> TestSequin.GenerationSequence:
            """Return a generation sequence."""
            # Signal that there is only one value.
            draw(strategies.just(None))
            return TestSequin.GenerationSequence(
                bitseq("110101011111001"),
                [
                    (1, 0),
                    (5, 3),
                    (5, 3),
                    (5, 1),
                    (5, sequin.SequinExhaustedError),
                    (1, sequin.SequinExhaustedError),
                ],
            )

    @hypothesis.given(sequence=GenerationSequence.strategy())
    @hypothesis.example(
        sequence=GenerationSequence(
            bitseq("110101011111001"),
            [
                (1, 0),
                (5, 3),
                (5, 3),
                (5, 1),
                (5, sequin.SequinExhaustedError),
                (1, sequin.SequinExhaustedError),
            ],
        )
    )
    def test_generating(self, sequence: GenerationSequence) -> None:
        """The sequin generates deterministic sequences."""
        seq = sequin.Sequin(sequence.bit_sequence, is_bitstring=True)
        for i, (num, result) in enumerate(sequence.steps, start=1):
            if isinstance(result, int):
                assert seq.generate(num) == result, (
                    f"Failed to generate {result:d} in step {i}"
                )
            else:
                # Can't use pytest.raises here, because the assertion error
                # message is not customizable and we would lose information
                # about which step we're executing.
                with contextlib.suppress(sequin.SequinExhaustedError):
                    result2 = seq.generate(num)
                    pytest.fail(
                        f"Expected to be exhausted in step {i}, "
                        f"but generated {result2:d} instead"
                    )

    def test_generating_errors(self) -> None:
        """The sequin errors deterministically when generating sequences."""
        seq = sequin.Sequin(
            [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1], is_bitstring=True
        )
        with pytest.raises(ValueError, match="invalid target range"):
            seq.generate(0)

    @hypothesis.given(sequence=GenerationSequence.strategy())
    @hypothesis.example(
        sequence=GenerationSequence(
            bitseq("110101011111001"),
            [
                (1, 0),
                (5, 3),
                (5, 3),
                (5, 1),
                (5, sequin.SequinExhaustedError),
                (1, sequin.SequinExhaustedError),
            ],
        )
    )
    def test_internal_generating(self, sequence: GenerationSequence) -> None:
        """The sequin internals generate deterministic sequences."""
        seq = sequin.Sequin(sequence.bit_sequence, is_bitstring=True)
        for i, (num, result) in enumerate(sequence.steps, start=1):
            if num == 1:
                assert seq._generate_inner(num) == 0, (
                    f"Failed to generate {result:d} in step {i}"
                )
            elif isinstance(result, int):
                assert seq._generate_inner(num) == result, (
                    f"Failed to generate {result:d} in step {i}"
                )
            else:
                result2 = seq._generate_inner(num)
                assert result2 == num, (
                    f"Expected to be exhausted in step {i}, "
                    f"but generated {result2:d} instead"
                )

    def test_internal_generating_errors(self) -> None:
        """The sequin generation internals error deterministically."""
        seq = sequin.Sequin(
            [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1], is_bitstring=True
        )
        with pytest.raises(ValueError, match="invalid target range"):
            seq._generate_inner(0)
        with pytest.raises(ValueError, match="invalid base:"):
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

        # TODO(the-13th-letter): Check feasibility of encoding
        # unsatisfiable shifts.
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
                ).flatmap(strategies.permutations),
                label="sequence of bit shift sizes",
            )
            bit_sequence: list[int] = []
            steps: list[tuple[int, Sequence[int], list[int]]] = []
            for i, count in enumerate(counts):
                shift_result = draw(
                    strategies.lists(
                        bits_strategy, min_size=count, max_size=count
                    ),
                    label=f"shift result #{i}",
                )
                for step in steps[:i]:
                    step[2].extend(shift_result)
                bit_sequence.extend(shift_result)
                steps.append((count, shift_result, []))
            return TestSequin.ShiftSequence(bit_sequence, steps)

    @hypothesis.given(sequence=ShiftSequence.strategy())
    @hypothesis.example(
        sequence=ShiftSequence(
            bitseq("1010010001"),
            [
                (3, bitseq("101"), bitseq("0010001")),
                (3, bitseq("001"), bitseq("0001")),
                (5, bitseq(""), bitseq("0001")),
                (4, bitseq("0001"), bitseq("")),
            ],
        )
    )
    def test_shifting(self, sequence: ShiftSequence) -> None:
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
                f"At step {i}, the shifting result differs"
            )
            if remaining:
                assert seq.bases[2] == collections.deque(remaining), (
                    f"After step {i}, the remaining bit sequence differs"
                )
            else:
                assert 2 not in seq.bases, (
                    f"After step {i}, the bit sequence is not exhausted yet"
                )

    @Parametrize.INVALID_SEQUIN_INPUTS
    def test_constructor_exceptions(
        self,
        sequence: list[int] | str,
        is_bitstring: bool,
        exc_type: type[Exception],
        exc_pattern: str,
    ) -> None:
        """The sequin raises on invalid bit and integer sequences."""
        with pytest.raises(exc_type, match=exc_pattern):
            sequin.Sequin(sequence, is_bitstring=is_bitstring)


class SequinStateMachine(stateful.RuleBasedStateMachine):
    r"""A state machine for the sequin.

    Compares the output of [`sequin.Sequin.generate`][] with the output
    of a 1-to-1 translation of the original JavaScript Sequin code.

    """

    ORIGINAL_SOURCE = r"""
        'use strict';

        var Stream = function(sequence, bits) {
          bits = bits || (sequence instanceof Buffer ? 8 : 1);
          var binary = '', b, i, n;

          for (i = 0, n = sequence.length; i < n; i++) {
            b = this._get(sequence, i).toString(2);
            while (b.length < bits) b = '0' + b;
            binary = binary + b;
          }
          binary = binary.split('').map(function(b) { return parseInt(b, 2) });

          this._bases = {'2': binary};
        };

        Stream.prototype.generate = function(n, base, inner) {
          base = base || 2;

          var value = n,
              k = Math.ceil(Math.log(n) / Math.log(base)),
              r = Math.pow(base, k) - n,
              chunk;

          loop: while (value >= n) {
            chunk = this._shift(base, k);
            if (!chunk) return inner ? n : null;

            value = this._evaluate(chunk, base);

            if (value >= n) {
              if (r === 1) continue loop;
              this._push(r, value - n);
              value = this.generate(n, r, true);
            }
          }
          return value;
        };

        Stream.prototype._get = function(sequence, i) {
          return sequence.readUInt8 ? sequence.readUInt8(i) : sequence[i];
        };

        Stream.prototype._evaluate = function(chunk, base) {
          var sum = 0,
              i   = chunk.length;

          while (i--) sum += chunk[i] * Math.pow(base, chunk.length - (i+1));
          return sum;
        };

        Stream.prototype._push = function(base, value) {
          this._bases[base] = this._bases[base] || [];
          this._bases[base].push(value);
        };

        Stream.prototype._shift = function(base, k) {
          var list = this._bases[base];
          if (!list || list.length < k) return null;
          else return list.splice(0,k);
        };

        module.exports = Stream;
    """
    """
    The original JavaScript code: Sequin 0.1.1, Copyright 2017 James
    Coglan.  Released under the following MIT License:

        Copyright (c) 2012-2017 James Coglan

        Permission is hereby granted, free of charge, to any person obtaining a copy of
        this software and associated documentation files (the 'Software'), to deal in
        the Software without restriction, including without limitation the rights to
        use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
        the Software, and to permit persons to whom the Software is furnished to do so,
        subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all
        copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
        FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
        COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
        IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    """

    class Stream:  # pragma: no cover
        def __init__(
            self,
            sequence: bytes | bytearray | Sequence[int],
            bits: int | None = None,
        ) -> None:
            r"""Initialize the stream.

            Corresponding JavaScript source:

                var Stream = function(sequence, bits) {
                  bits = bits || (sequence instanceof Buffer ? 8 : 1);
                  var binary = '', b, i, n;

                  for (i = 0, n = sequence.length; i < n; i++) {
                    b = this._get(sequence, i).toString(2);
                    while (b.length < bits) b = '0' + b;
                    binary = binary + b;
                  }
                  binary = binary.split('').map(function(b) { return parseInt(b, 2) });

                  this._bases = {'2': binary};
                };

            """
            bits = (
                bits
                if bits is not None
                else 8
                if isinstance(sequence, (bytes, bytearray))
                else 1
            )
            binary = ""
            b: str
            i: int
            n = len(sequence)

            for i in range(n):
                b = "{:b}".format(self._get(sequence, i))  # noqa: UP032
                while len(b) < bits:
                    b = "0" + b
                binary = binary + b  # noqa: PLR6104
            binary_ = list(map(lambda b: int(b, 2), list(binary)))  # noqa: C417

            self._bases = {2: binary_}

        def generate(self, n: int, base: int = 2) -> int | None:
            r"""Main method "generate".

            Corresponding JavaScript source:

                Stream.prototype.generate = function(n, base, inner) {
                  base = base || 2;

                  var value = n,
                      k = Math.ceil(Math.log(n) / Math.log(base)),
                      r = Math.pow(base, k) - n,
                      chunk;

                  loop: while (value >= n) {
                    chunk = this._shift(base, k);
                    if (!chunk) return inner ? n : null;

                    value = this._evaluate(chunk, base);

                    if (value >= n) {
                      if (r === 1) continue loop;
                      this._push(r, value - n);
                      value = this.generate(n, r, true);
                    }
                  }
                  return value;
                };

            ...except that we hardcode `inner` to False, for typing
            reasons.  ([`_generate_inner`][] is the version with `inner`
            hardcoded to True.)

            """
            value: int = n
            k = math.ceil(math.log(n) / math.log(base))
            r = pow(base, k) - n
            chunk: Sequence[int] | None

            while value >= n:
                chunk = self._shift(base, k)
                if not chunk:
                    return None

                value = self._evaluate(chunk, base)

                if value >= n:
                    if r == 1:
                        continue
                    self._push(r, value - n)
                    value = self._generate_inner(n, r)
            return value

        def _generate_inner(self, n: int, base: int = 2) -> int:
            r"""Helper method.

            Corresponding JavaScript source:

                Stream.prototype.generate = function(n, base, inner) {
                  base = base || 2;

                  var value = n,
                      k = Math.ceil(Math.log(n) / Math.log(base)),
                      r = Math.pow(base, k) - n,
                      chunk;

                  loop: while (value >= n) {
                    chunk = this._shift(base, k);
                    if (!chunk) return inner ? n : null;

                    value = this._evaluate(chunk, base);

                    if (value >= n) {
                      if (r === 1) continue loop;
                      this._push(r, value - n);
                      value = this.generate(n, r, true);
                    }
                  }
                  return value;
                };

            ...except that we hardcode `inner` to True, for typing
            reasons.  ([`generate`][] is the version with `inner`
            hardcoded to False.)

            """
            value: int = n
            k = math.ceil(math.log(n) / math.log(base))
            r = pow(base, k) - n
            chunk: Sequence[int] | None

            while value >= n:
                chunk = self._shift(base, k)
                if not chunk:
                    return n

                value = self._evaluate(chunk, base)

                if value >= n:
                    if r == 1:
                        continue
                    self._push(r, value - n)
                    value = self._generate_inner(n, r)
            return value

        @staticmethod
        def _get(sequence: bytes | bytearray | Sequence[int], i: int) -> int:
            r"""Helper method.

            Corresponding JavaScript source:

                Stream.prototype._get = function(sequence, i) {
                  return sequence.readUInt8 ? sequence.readUInt8(i) : sequence[i];
                };

            """
            return (
                sequence[i]  # noqa: RUF034
                if isinstance(sequence, (bytes, bytearray))
                else sequence[i]
            )

        @staticmethod
        def _evaluate(chunk: Sequence[int], base: int) -> int:
            r"""Helper method.

            Corresponding JavaScript source:

                Stream.prototype._evaluate = function(chunk, base) {
                  var sum = 0,
                      i   = chunk.length;

                  while (i--) sum += chunk[i] * Math.pow(base, chunk.length - (i+1));
                  return sum;
                };

            """
            sum_ = 0
            i = len(chunk)
            while i > 0:
                i -= 1
                sum_ += chunk[i] * pow(base, len(chunk) - (i + 1))
            return sum_

        def _push(self, base: int, value: int) -> None:
            r"""Helper method.

            Corresponding JavaScript source:

                Stream.prototype._push = function(base, value) {
                  this._bases[base] = this._bases[base] || [];
                  this._bases[base].push(value);
                };

            """
            self._bases.setdefault(base, [])
            self._bases[base].append(value)

        def _shift(self, base: int, k: int) -> Sequence[int] | None:
            r"""Helper method.

            Corresponding JavaScript source:

                Stream.prototype._shift = function(base, k) {
                  var list = this._bases[base];
                  if (!list || list.length < k) return null;
                  else return list.splice(0,k);
                };

            """
            list_ = self._bases[base]
            if not list_ or len(list_) < k:
                return None
            else:  # noqa: RET505
                result = list_[0:k]
                list_[0:k] = []
                return result

    def __init__(self) -> None:
        """Initialize this state machine."""
        super().__init__()
        self.reference_sequin: SequinStateMachine.Stream
        self.sequin: sequin.Sequin

    @stateful.initialize(
        sequence=strategies.one_of(
            strategies.lists(strategies.integers(0, 1)), strategies.binary()
        )
    )
    def _init(self, sequence: bytes | bytearray | list[int]) -> None:
        if isinstance(sequence, (bytes, bytearray)):
            self.reference_sequin = SequinStateMachine.Stream(bytes(sequence))
            self.sequin = sequin.Sequin(bytes(sequence), is_bitstring=False)
        else:
            self.reference_sequin = SequinStateMachine.Stream(sequence.copy())
            self.sequin = sequin.Sequin(sequence.copy(), is_bitstring=True)

    @staticmethod
    def normalize_bases_structure(
        bases: dict[int, list[int]] | dict[int, collections.deque[int]],
    ) -> list[tuple[int, tuple[int, ...]]]:
        return sorted((k, tuple(v)) for k, v in bases.items() if v)

    @stateful.invariant()
    def check_sequin_state(self) -> None:
        reference_bases = self.reference_sequin._bases
        sequin_bases = self.sequin.bases
        assert self.normalize_bases_structure(
            reference_bases
        ) == self.normalize_bases_structure(sequin_bases)

    @stateful.rule(n=strategies.integers(1, 128))
    def generate(self, n: int) -> None:
        value1 = self.reference_sequin.generate(n)
        try:
            value2 = self.sequin.generate(n)
        except sequin.SequinExhaustedError:
            value2 = None
        if n == 1:
            # As per upstream's own tests, Sequin.generate(1) should
            # return 0, and we do.  But the original JavaScript version
            # returns `null`.  Therefore, just assert that both are
            # equally falsy.
            assert not value1
            assert not value2
        else:
            assert value1 == value2


@pytest_machinery.heavy_duty
class TestStateAgainstReferenceSequin(SequinStateMachine.TestCase):  # type: ignore[misc,valid-type]
    pass
