# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Work-alike of vault(1) – a deterministic, stateless password manager"""  # noqa: RUF002

from __future__ import annotations

import base64
import collections
import hashlib
import math
import unicodedata

from typing_extensions import assert_type

import sequin
import ssh_agent_client

__author__ = 'Marco Ricci <m@the13thletter.info>'
__version__ = '0.1.2'


class AmbiguousByteRepresentationError(ValueError):
    """The object has an ambiguous byte representation."""
    def __init__(self):
        super().__init__('text string has ambiguous byte representation')


_CHARSETS = collections.OrderedDict([
    ('lower', b'abcdefghijklmnopqrstuvwxyz'),
    ('upper', b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
    ('alpha', b''),  # Placeholder.
    ('number', b'0123456789'),
    ('alphanum', b''),  # Placeholder.
    ('space', b' '),
    ('dash', b'-_'),
    ('symbol', b'!"#$%&\'()*+,./:;<=>?@[\\]^{|}~-_'),
    ('all', b''),  # Placeholder.
])
_CHARSETS['alpha'] = _CHARSETS['lower'] + _CHARSETS['upper']
_CHARSETS['alphanum'] = _CHARSETS['alpha'] + _CHARSETS['number']
_CHARSETS['all'] = (
    _CHARSETS['alphanum'] + _CHARSETS['space'] + _CHARSETS['symbol']
)


class Vault:
    """A work-alike of James Coglan's vault.

    Store settings for generating (actually: deriving) passphrases for
    named services, with various constraints, given only a master
    passphrase.  Also, actually generate the passphrase.  The derivation
    is deterministic and non-secret; only the master passphrase need be
    kept secret.  The implementation is compatible with [vault][].

    [James Coglan explains the passphrase derivation algorithm in great
    detail][ALGORITHM] in his blog post on said topic: A principally
    infinite bit stream is obtained by running a key-derivation function
    on the master passphrase and the service name, then this bit stream
    is fed into a [Sequin][sequin.Sequin] to generate random numbers in
    the correct range, and finally these random numbers select
    passphrase characters until the desired length is reached.

    [vault]: https://getvau.lt
    [ALGORITHM]: https://blog.jcoglan.com/2012/07/16/designing-vaults-generator-algorithm/

    """

    _UUID = b'e87eb0f4-34cb-46b9-93ad-766c5ab063e7'
    """A tag used by vault in the bit stream generation."""
    _CHARSETS = _CHARSETS
    """
        Known character sets from which to draw passphrase characters.
        Relies on a certain, fixed order for their definition and their
        contents.

    """

    def __init__(
        self,
        *,
        phrase: bytes | bytearray | str = b'',
        length: int = 20,
        repeat: int = 0,
        lower: int | None = None,
        upper: int | None = None,
        number: int | None = None,
        space: int | None = None,
        dash: int | None = None,
        symbol: int | None = None,
    ) -> None:
        """Initialize the Vault object.

        Args:
            phrase:
                The master passphrase from which to derive the service
                passphrases.  If a text string, then the byte
                representation must be unique.
            length:
                Desired passphrase length.
            repeat:
                The maximum number of immediate character repetitions
                allowed in the passphrase.  Disabled if set to 0.
            lower:
                Optional constraint on ASCII lowercase characters.  If
                positive, include this many lowercase characters
                somewhere in the passphrase.  If 0, avoid lowercase
                characters altogether.
            upper:
                Same as `lower`, but for ASCII uppercase characters.
            number:
                Same as `lower`, but for ASCII digits.
            space:
                Same as `lower`, but for the space character.
            dash:
                Same as `lower`, but for the hyphen-minus and underscore
                characters.
            symbol:
                Same as `lower`, but for all other hitherto unlisted
                ASCII printable characters (except backquote).

        Raises:
            AmbiguousByteRepresentationError:
                The phrase is a text string with differing NFC- and
                NFD-normalized UTF-8 byte representations.

        """
        self._phrase = self._get_binary_string(phrase)
        self._length = length
        self._repeat = repeat
        self._allowed = bytearray(self._CHARSETS['all'])
        self._required: list[bytes] = []

        def subtract_or_require(
            count: int | None, characters: bytes | bytearray
        ) -> None:
            if not isinstance(count, int):
                return
            if count <= 0:
                self._allowed = self._subtract(characters, self._allowed)
            else:
                for _ in range(count):
                    self._required.append(characters)

        subtract_or_require(lower, self._CHARSETS['lower'])
        subtract_or_require(upper, self._CHARSETS['upper'])
        subtract_or_require(number, self._CHARSETS['number'])
        subtract_or_require(space, self._CHARSETS['space'])
        subtract_or_require(dash, self._CHARSETS['dash'])
        subtract_or_require(symbol, self._CHARSETS['symbol'])
        if len(self._required) > self._length:
            msg = 'requested passphrase length too short'
            raise ValueError(msg)
        if not self._allowed:
            msg = 'no allowed characters left'
            raise ValueError(msg)
        for _ in range(len(self._required), self._length):
            self._required.append(bytes(self._allowed))

    def _entropy(self) -> float:
        """Estimate the passphrase entropy, given the current settings.

        The entropy is the base 2 logarithm of the amount of
        possibilities.  We operate directly on the logarithms, and use
        sorting and [`math.fsum`][] to keep high accuracy.

        Note:
            We actually overestimate the entropy here because of poor
            handling of character repetitions.  In the extreme, assuming
            that only one character were allowed, then because there is
            only one possible string of each given length, the entropy
            of that string `s` is always be zero.  However, we calculate
            the entropy as `math.log2(math.factorial(len(s)))`, i.e. we
            assume the characters at the respective string position are
            distinguishable from each other.

        Returns:
            A valid (and somewhat close) upper bound to the entropy.

        """
        factors: list[int] = []
        if not self._required or any(not x for x in self._required):
            return float('-inf')
        for i, charset in enumerate(self._required):
            factors.extend([i + 1, len(charset)])
        factors.sort()
        return math.fsum(math.log2(f) for f in factors)

    def _estimate_sufficient_hash_length(
        self,
        safety_factor: float = 2.0,
    ) -> int:
        """Estimate the sufficient hash length, given the current settings.

        Using the entropy (via `_entropy`) and a safety factor, give an
        initial estimate of the length to use for `create_hash` such
        that using a `Sequin` with this hash will not exhaust it during
        passphrase generation.

        Args:
            safety_factor: The safety factor.  Must be at least 1.

        Returns:
            The estimated sufficient hash length.

        Warning:
            This is a heuristic, not an exact computation; it may
            underestimate the true necessary hash length.  It is
            intended as a starting point for searching for a sufficient
            hash length, usually by doubling the hash length each time
            it does not yet prove so.

        """
        try:
            safety_factor = float(safety_factor)
        except TypeError as e:
            msg = f'invalid safety factor: not a float: {safety_factor!r}'
            raise TypeError(msg) from e
        if not math.isfinite(safety_factor) or safety_factor < 1.0:
            msg = f'invalid safety factor {safety_factor!r}'
            raise ValueError(msg)
        # Ensure the bound is strictly positive.
        entropy_bound = max(1, self._entropy())
        return int(math.ceil(safety_factor * entropy_bound / 8))

    @staticmethod
    def _get_binary_string(s: bytes | bytearray | str, /) -> bytes:
        """Convert the input string to a read-only, binary string.

        If it is a text string, then test for an unambiguous UTF-8
        representation, otherwise abort.  (That is, check whether the
        NFC and NFD forms of the string coincide.)

        Args:
            s: The string to (check and) convert.

        Returns:
            A read-only, binary copy of the string.

        Raises:
            AmbiguousByteRepresentationError:
                The text string has differing NFC- and NFD-normalized
                UTF-8 byte representations.

        """
        if isinstance(s, str):
            norm = unicodedata.normalize
            if norm('NFC', s) != norm('NFD', s):
                raise AmbiguousByteRepresentationError
            return s.encode('UTF-8')
        return bytes(s)

    @classmethod
    def create_hash(
        cls,
        phrase: bytes | bytearray | str,
        service: bytes | bytearray,
        *,
        length: int = 32,
    ) -> bytes:
        r"""Create a pseudorandom byte stream from phrase and service.

        Create a pseudorandom byte stream from `phrase` and `service` by
        feeding them into the key-derivation function PBKDF2
        (8 iterations, using SHA-1).

        Args:
            phrase:
                A master passphrase, or sometimes an SSH signature.
                Used as the key for PBKDF2, the underlying cryptographic
                primitive.

                If a text string, then the byte representation must be
                unique.
            service:
                A vault service name.  Will be suffixed with
                `Vault._UUID`, and then used as the salt value for
                PBKDF2.
            length:
                The length of the byte stream to generate.

        Returns:
            A pseudorandom byte string of length `length`.

        Raises:
            AmbiguousByteRepresentationError:
                The phrase is a text string with differing NFC- and
                NFD-normalized UTF-8 byte representations.

        Note:
            Shorter values returned from this method (with the same key
            and message) are prefixes of longer values returned from
            this method.  (This property is inherited from the
            underlying PBKDF2 function.)  It is thus safe (if slow) to
            call this method with the same input with ever-increasing
            target lengths.

        Examples:
            >>> # See also Vault.phrase_from_key examples.
            >>> phrase = bytes.fromhex('''
            ... 00 00 00 0b 73 73 68 2d 65 64 32 35 35 31 39
            ... 00 00 00 40
            ... f0 98 19 80 6c 1a 97 d5 26 03 6e cc e3 65 8f 86
            ... 66 07 13 19 13 09 21 33 33 f9 e4 36 53 1d af fd
            ... 0d 08 1f ec f8 73 9b 8c 5f 55 39 16 7c 53 54 2c
            ... 1e 52 bb 30 ed 7f 89 e2 2f 69 51 55 d8 9e a6 02
            ... ''')
            >>> Vault.create_hash(phrase, b'some_service', length=4)
            b'M\xb1<S'
            >>> Vault.create_hash(phrase, b'some_service', length=16)
            b'M\xb1<S\x827E\xd1M\xaf\xf8~\xc8n\x10\xcc'
            >>> Vault.create_hash(phrase, b'NOSUCHSERVICE', length=16)
            b'\x1c\xc3\x9c\xd9\xb6\x1a\x99CS\x07\xc41\xf4\x85#s'

        """
        phrase = cls._get_binary_string(phrase)
        assert not isinstance(phrase, str)
        salt = bytes(service) + cls._UUID
        return hashlib.pbkdf2_hmac(
            hash_name='sha1',
            password=phrase,
            salt=salt,
            iterations=8,
            dklen=length,
        )

    def generate(
        self,
        service_name: str | bytes | bytearray,
        /,
        *,
        phrase: bytes | bytearray | str = b'',
    ) -> bytes:
        r"""Generate a service passphrase.

        Args:
            service_name:
                The service name.
            phrase:
                If given, override the passphrase given during
                construction.

                If a text string, then the byte representation must be
                unique.

        Returns:
            The service passphrase.

        Raises:
            AmbiguousByteRepresentationError:
                The phrase is a text string with differing NFC- and
                NFD-normalized UTF-8 byte representations.

        Examples:
            >>> phrase = b'She cells C shells bye the sea shoars'
            >>> # Using default options in constructor.
            >>> Vault(phrase=phrase).generate(b'google')
            b': 4TVH#5:aZl8LueOT\\{'
            >>> # Also possible:
            >>> Vault().generate(b'google', phrase=phrase)
            b': 4TVH#5:aZl8LueOT\\{'

        """
        hash_length = self._estimate_sufficient_hash_length()
        assert hash_length >= 1
        # Ensure the phrase is a bytes object.  Needed later for safe
        # concatenation.
        if isinstance(service_name, str):
            service_name = service_name.encode('utf-8')
        elif not isinstance(service_name, bytes):
            service_name = bytes(service_name)
        assert_type(service_name, bytes)
        if not phrase:
            phrase = self._phrase
        phrase = self._get_binary_string(phrase)
        # Repeat the passphrase generation with ever-increasing hash
        # lengths, until the passphrase can be formed without exhausting
        # the sequin.  See the guarantee in the create_hash method for
        # why this works.
        while True:
            try:
                required = self._required[:]
                seq = sequin.Sequin(
                    self.create_hash(
                        phrase=phrase, service=service_name, length=hash_length
                    )
                )
                result = bytearray()
                while len(result) < self._length:
                    pos = seq.generate(len(required))
                    charset = required.pop(pos)
                    # Determine if an unlucky choice right now might
                    # violate the restriction on repeated characters.
                    # That is, check if the current partial passphrase
                    # ends with r - 1 copies of the same character
                    # (where r is the repeat limit that must not be
                    # reached), and if so, remove this same character
                    # from the current character's allowed set.
                    if self._repeat and result:
                        bad_suffix = bytes(result[-1:]) * (self._repeat - 1)
                        if result.endswith(bad_suffix):
                            charset = self._subtract(
                                bytes(result[-1:]), charset
                            )
                    pos = seq.generate(len(charset))
                    result.extend(charset[pos : pos + 1])
            except sequin.SequinExhaustedError:
                hash_length *= 2
            else:
                return bytes(result)

    @staticmethod
    def _is_suitable_ssh_key(key: bytes | bytearray, /) -> bool:
        """Check whether the key is suitable for passphrase derivation.

        Currently, this only checks whether signatures with this key
        type are deterministic.

        Args:
            key: SSH public key to check.

        Returns:
            True if and only if the key is suitable for use in deriving
            a passphrase deterministically.

        """
        deterministic_signature_types = {
            'ssh-ed25519': lambda k: k.startswith(
                b'\x00\x00\x00\x0bssh-ed25519'
            ),
            'ssh-ed448': lambda k: k.startswith(b'\x00\x00\x00\x09ssh-ed448'),
            'ssh-rsa': lambda k: k.startswith(b'\x00\x00\x00\x07ssh-rsa'),
        }
        return any(v(key) for v in deterministic_signature_types.values())

    @classmethod
    def phrase_from_key(cls, key: bytes | bytearray, /) -> bytes:
        """Obtain the master passphrase from a configured SSH key.

        vault allows the usage of certain SSH keys to derive a master
        passphrase, by signing the vault UUID with the SSH key.  The key
        type must ensure that signatures are deterministic.

        Args:
            key: The (public) SSH key to use for signing.

        Returns:
            The signature of the vault UUID under this key, unframed but
            encoded in base64.

        Raises:
            ValueError:
                The SSH key is principally unsuitable for this use case.
                Usually this means that the signature is not
                deterministic.

        Examples:
            >>> import base64
            >>> # Actual Ed25519 test public key.
            >>> public_key = bytes.fromhex('''
            ... 00 00 00 0b 73 73 68 2d 65 64 32 35 35 31 39
            ... 00 00 00 20
            ... 81 78 81 68 26 d6 02 48 5f 0f ff 32 48 6f e4 c1
            ... 30 89 dc 1c 6a 45 06 09 e9 09 0f fb c2 12 69 76
            ... ''')
            >>> expected_sig_raw = bytes.fromhex('''
            ... 00 00 00 0b 73 73 68 2d 65 64 32 35 35 31 39
            ... 00 00 00 40
            ... f0 98 19 80 6c 1a 97 d5 26 03 6e cc e3 65 8f 86
            ... 66 07 13 19 13 09 21 33 33 f9 e4 36 53 1d af fd
            ... 0d 08 1f ec f8 73 9b 8c 5f 55 39 16 7c 53 54 2c
            ... 1e 52 bb 30 ed 7f 89 e2 2f 69 51 55 d8 9e a6 02
            ... ''')
            >>> # Raw Ed25519 signatures are 64 bytes long.
            >>> signature_blob = expected_sig_raw[-64:]
            >>> phrase = base64.standard_b64encode(signature_blob)
            >>> Vault.phrase_from_key(phrase) == expected  # doctest:+SKIP
            True

        """
        if not cls._is_suitable_ssh_key(key):
            msg = (
                'unsuitable SSH key: bad key, or '
                'signature not deterministic'
            )
            raise ValueError(msg)
        with ssh_agent_client.SSHAgentClient() as client:
            raw_sig = client.sign(key, cls._UUID)
        _keytype, trailer = client.unstring_prefix(raw_sig)
        signature_blob = client.unstring(trailer)
        return bytes(base64.standard_b64encode(signature_blob))

    @staticmethod
    def _subtract(
        charset: bytes | bytearray,
        allowed: bytes | bytearray,
    ) -> bytearray:
        """Remove the characters in charset from allowed.

        This preserves the relative order of characters in `allowed`.

        Args:
            charset:
                Characters to remove.  Must not contain duplicate
                characters.
            allowed:
                Character set to remove the other characters from.  Must
                not contain duplicate characters.

        Returns:
            The pruned "allowed" character set.

        Raises:
            ValueError:
                `allowed` or `charset` contained duplicate characters.

        """
        allowed = (
            allowed if isinstance(allowed, bytearray) else bytearray(allowed)
        )
        assert_type(allowed, bytearray)
        msg_dup_characters = 'duplicate characters in set'
        if len(frozenset(allowed)) != len(allowed):
            raise ValueError(msg_dup_characters)
        if len(frozenset(charset)) != len(charset):
            raise ValueError(msg_dup_characters)
        for c in charset:
            try:
                pos = allowed.index(c)
            except ValueError:
                pass
            else:
                allowed[pos : pos + 1] = []
        return allowed
