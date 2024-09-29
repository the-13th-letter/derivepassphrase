# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""A Python reimplementation of James Coglan's "sequin" Node.js module.

James Coglan's "sequin" Node.js module provides a pseudorandom number
generator (using rejection sampling on a stream of input numbers) that
attempts to minimize the amount of information it throws away:
(non-degenerate) rejected samples are fed into a stream of higher-order
numbers from which the next random number generation request will be
served.  The sequin module is used in Coglan's "vault" module (a
deterministic, stateless password manager that recomputes passwords
instead of storing them), and this reimplementation is used for
a similar purpose.

The main API is the [`Sequin`][] class, which is thoroughly documented.

"""

# ruff: noqa: RUF002,RUF003

from __future__ import annotations

import collections
from typing import TYPE_CHECKING

from typing_extensions import assert_type

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

__all__ = ('Sequin', 'SequinExhaustedError')
__author__ = 'Marco Ricci <software@the13thletter.info>'


class Sequin:
    """Generate pseudorandom non-negative numbers in different ranges.

    Given a (presumed high-quality) uniformly random sequence of input
    bits, generate pseudorandom non-negative integers in a certain range
    on each call of the `generate` method.  (It is permissible to
    specify a different range per call to `generate`; this is the main
    use case.)  We use a modified version of rejection sampling, where
    rejected values are stored in "rejection queues" if possible, and
    these rejection queues re-seed the next round of rejection sampling.

    This is a Python reimplementation of James Coglan's [Node.js sequin
    module][JS_SEQUIN], as introduced in [his blog post][BLOG_POST].  It
    uses a [technique by Christian Lawson-Perfect][SEQUIN_TECHNIQUE].
    I do not know why the original module is called "sequin"; I presume
    it to be a pun on "sequence".

    [JS_SEQUIN]: https://www.npmjs.com/package/sequin
    [BLOG_POST]: https://blog.jcoglan.com/2012/07/16/designing-vaults-generator-algorithm/
    [SEQUIN_TECHNIQUE]: https://checkmyworking.com/2012/06/converting-a-stream-of-binary-digits-to-a-stream-of-base-n-digits/

    """

    def __init__(
        self,
        sequence: str | bytes | bytearray | Sequence[int],
        /,
        *,
        is_bitstring: bool = False,
    ) -> None:
        """Initialize the Sequin.

        Args:
            sequence:
                A sequence of bits, or things convertible to bits, to
                seed the pseudorandom number generator.  Byte and text
                strings are converted to 8-bit integer sequences.
                (Conversion will fail if the text string contains
                non-ISO-8859-1 characters.)  The numbers are then
                converted to bits.
            is_bitstring:
                If true, treat the input as a bitstring.  By default,
                the input is treated as a string of 8-bit integers, from
                which the individual bits must still be extracted.

        Raises:
            ValueError:
                The sequence contains values outside the permissible
                range.

        """
        msg = 'sequence item out of range'

        def uint8_to_bits(value: int) -> Iterator[int]:
            """Yield individual bits of an 8-bit number, MSB first."""
            for i in (0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01):
                yield 1 if value | i == value else 0

        if isinstance(sequence, str):
            try:
                sequence = tuple(sequence.encode('iso-8859-1'))
            except UnicodeError as e:
                raise ValueError(msg) from e
        else:
            sequence = tuple(sequence)
        assert_type(sequence, tuple[int, ...])
        self.bases: dict[int, collections.deque[int]] = {}

        def gen() -> Iterator[int]:
            for num in sequence:
                if num not in range(2 if is_bitstring else 256):
                    raise ValueError(msg)
                if is_bitstring:
                    yield num
                else:
                    yield from uint8_to_bits(num)

        self.bases[2] = collections.deque(gen())

    def _all_or_nothing_shift(
        self, count: int, /, *, base: int = 2
    ) -> Sequence[int]:
        """Shift and return items if and only if there are enough.

        Args:
            count: Number of items to shift/consume.
            base: Use the base `base` sequence.

        Returns:
            If there are sufficient items in the sequence left, then
            consume them from the sequence and return them.  Otherwise,
            consume nothing, and return nothing.

        Notes:
            We currently remove now-empty sequences from the registry of
            sequences.

        Examples:
            >>> seq = Sequin([1, 0, 1, 0, 0, 1, 0, 0, 0, 1], is_bitstring=True)
            >>> seq.bases
            {2: deque([1, 0, 1, 0, 0, 1, 0, 0, 0, 1])}
            >>> seq._all_or_nothing_shift(3)
            (1, 0, 1)
            >>> seq._all_or_nothing_shift(3)
            (0, 0, 1)
            >>> seq.bases[2]
            deque([0, 0, 0, 1])
            >>> seq._all_or_nothing_shift(5)
            ()
            >>> seq.bases[2]
            deque([0, 0, 0, 1])
            >>> seq._all_or_nothing_shift(4)
            (0, 0, 0, 1)
            >>> 2 in seq.bases  # now-empty sequences are removed
            False

        """
        try:
            seq = self.bases[base]
        except KeyError:
            return ()
        stash: collections.deque[int] = collections.deque()
        try:
            for _ in range(count):
                stash.append(seq.popleft())
        except IndexError:
            seq.extendleft(reversed(stash))
            return ()
        # Clean up queues.
        if not seq:
            del self.bases[base]
        return tuple(stash)

    @staticmethod
    def _big_endian_number(digits: Sequence[int], /, *, base: int = 2) -> int:
        """Evaluate the given integer sequence as a big endian number.

        Args:
            digits: A sequence of integers to evaluate.
            base: The number base to evaluate those integers in.

        Returns:
            The number value of the integer sequence.

        Raises:
            ValueError: `base` is an invalid base.
            ValueError: Not all integers are valid base `base` digits.

        Examples:
            >>> Sequin._big_endian_number([1, 2, 3, 4, 5, 6, 7, 8], base=10)
            12345678
            >>> Sequin._big_endian_number([1, 2, 3, 4, 5, 6, 7, 8], base=100)
            102030405060708
            >>> Sequin._big_endian_number([0, 0, 0, 0, 1, 4, 9, 7], base=10)
            1497
            >>> Sequin._big_endian_number([1, 0, 0, 1, 0, 0, 0, 0], base=2)
            144
            >>> Sequin._big_endian_number([1, 7, 5, 5], base=8) == 0o1755
            True

        """
        if base < 2:  # noqa: PLR2004
            msg = f'invalid base: {base!r}'
            raise ValueError(msg)
        ret = 0
        allowed_range = range(base)
        n = len(digits)
        for i in range(n):
            i2 = (n - 1) - i
            x = digits[i]
            if not isinstance(x, int):
                msg = f'not an integer: {x!r}'
                raise TypeError(msg)  # noqa: DOC501
            if x not in allowed_range:
                msg = f'invalid base {base!r} digit: {x!r}'
                raise ValueError(msg)
            ret += (base**i2) * x
        return ret

    def generate(self, n: int, /) -> int:
        """Generate a base `n` non-negative integer.

        We attempt to generate a value using rejection sampling.  If the
        generated sample is outside the desired range (i.e., is
        rejected), then attempt to reuse the sample by seeding
        a "higher-order" input sequence of uniformly random numbers (for
        a different base).

        Args:
            n:
                Generate numbers in the range 0, ..., `n` - 1.
                (Inclusive.)  Must be larger than 0.

        Returns:
            A pseudorandom number in the range 0, ..., `n` - 1.

        Raises:
            ValueError:
                The range is empty.
            SequinExhaustedError:
                The sequin is exhausted.

        Examples:
            >>> seq = Sequin(
            ...     [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1],
            ...     is_bitstring=True,
            ... )
            >>> seq2 = Sequin(
            ...     [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1],
            ...     is_bitstring=True,
            ... )
            >>> seq.generate(5)
            3
            >>> seq.generate(5)
            3
            >>> seq.generate(5)
            1
            >>> seq.generate(5)  # doctest: +IGNORE_EXCEPTION_DETAIL
            Traceback (most recent call last):
                ...
            SequinExhaustedError: Sequin is exhausted

            Using `n = 1` does not actually consume input bits:

            >>> seq2.generate(1)
            0

            But it still won't work on exhausted sequins:

            >>> seq.generate(1)  # doctest: +IGNORE_EXCEPTION_DETAIL
            Traceback (most recent call last):
                ...
            SequinExhaustedError: Sequin is exhausted

        """
        if 2 not in self.bases:  # noqa: PLR2004
            raise SequinExhaustedError
        value = self._generate_inner(n, base=2)
        if value == n:
            raise SequinExhaustedError
        return value

    def _generate_inner(self, n: int, /, *, base: int = 2) -> int:
        """Recursive call to generate a base `n` non-negative integer.

        We first determine the correct exponent `k` to generate base `n`
        numbers from a stream of base `base` numbers, then attempt to
        take `k` numbers from the base `base` sequence (or bail if not
        possible).  If the resulting number `v` is out of range for
        base `n`, then push `v - n` onto the rejection queue for
        base `r` (where `r = base ** k - n`), and attempt to generate
        the requested base `n` integer from the sequence of base `r`
        numbers next.  (This recursion is not attempted if `r` = 1.)
        Otherwise, return the number.

        Args:
            n:
                Generate numbers in the range 0, ..., `n - 1`.
                (Inclusive.)  Must be larger than 0.
            base:
                Use the base `base` sequence as a source for
                pseudorandom numbers.

        Returns:
            A pseudorandom number in the range 0, ..., `n - 1` if
            possible, or `n` if the stream is exhausted.

        Raises:
            ValueError:
                The range is empty.

        Examples:
            >>> seq = Sequin(
            ...     [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1],
            ...     is_bitstring=True,
            ... )
            >>> seq2 = Sequin(
            ...     [1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1],
            ...     is_bitstring=True,
            ... )
            >>> seq._generate_inner(5)
            3
            >>> seq._generate_inner(5)
            3
            >>> seq._generate_inner(5)
            1
            >>> seq._generate_inner(5)  # error condition: sequin exhausted
            5

            Using `n = 1` does not actually consume input bits, and
            always works, regardless of sequin exhaustion:

            >>> seq2._generate_inner(1)
            0
            >>> seq._generate_inner(1)
            0

            Using an unsuitable range will raise:

            >>> seq2._generate_inner(0)  # doctest: +IGNORE_EXCEPTION_DETAIL
            Traceback (most recent call last):
                ...
            ValueError: invalid target range

        """
        if n < 1:
            msg = 'invalid target range'
            raise ValueError(msg)
        if base < 2:  # noqa: PLR2004
            msg = f'invalid base: {base!r}'
            raise ValueError(msg)
        # p = base ** k, where k is the smallest integer such that
        # p >= n.  We determine p and k inductively.
        p = 1
        k = 0
        while p < n:
            p *= base
            k += 1
        # The remainder r of p and n is used as the base for rejection
        # queue.
        r = p - n
        # The generated number v is initialized to n because of the
        # while loop below.
        v = n
        while v > n - 1:
            list_slice = self._all_or_nothing_shift(k, base=base)
            if not list_slice:
                if n != 1:
                    return n
                v = 0
            v = self._big_endian_number(list_slice, base=base)
            if v > n - 1:
                # If r is 0, then p == n, so v < n, or rather
                # v <= n - 1.
                assert r > 0
                if r == 1:
                    continue
                self._stash(v - n, base=r)
                v = self._generate_inner(n, base=r)
        return v

    def _stash(self, value: int, /, *, base: int = 2) -> None:
        """Stash `value` on the base `base` sequence.

        Sets up the base `base` sequence if it does not yet exist.

        """
        if base not in self.bases:
            self.bases[base] = collections.deque()
        self.bases[base].append(value)


class SequinExhaustedError(Exception):
    """The sequin is exhausted.

    No more values can be generated from this sequin.

    """

    def __init__(self) -> None:  # noqa: D107
        super().__init__('Sequin is exhausted')
