# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Work-alike of vault(1) – a deterministic, stateless password manager

"""

from __future__ import annotations

import collections
import hashlib
import math
import warnings

from typing import assert_type, reveal_type

import sequin
import ssh_agent_client

__author__ = "Marco Ricci <m@the13thletter.info>"
__version__ = "0.1.0"

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
    _CHARSETS: collections.OrderedDict[str, bytes]
    """
        Known character sets from which to draw passphrase characters.
        Relies on a certain, fixed order for their definition and their
        contents.

    """
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
    _CHARSETS['all'] = (_CHARSETS['alphanum'] + _CHARSETS['space']
                        + _CHARSETS['symbol'])

    def __init__(
        self, *, phrase: bytes | bytearray = b'', length: int = 20,
        repeat: int = 0, lower: int | None = None,
        upper: int | None = None, number: int | None = None,
        space: int | None = None, dash: int | None = None,
        symbol: int | None = None,
    ) -> None:
        """Initialize the Vault object.

        Args:
            phrase:
                The master passphrase from which to derive the service
                passphrases.
            length:
                Desired passphrase length.
            repeat:
                The maximum number of immediate character repetitions
                allowed in the passphrase.  Disabled if set to 0.
            lower:
                Optional constraint on lowercase characters.  If
                positive, include this many lowercase characters
                somewhere in the passphrase.  If 0, avoid lowercase
                characters altogether.
            upper:
                Same as `lower`, but for uppercase characters.
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

        """
        self._phrase = bytes(phrase)
        self._length = length
        self._repeat = repeat
        self._allowed = bytearray(self._CHARSETS['all'])
        self._required: list[bytes] = []
        def subtract_or_require(
            count: int | None, characters: bytes | bytearray
        ) -> None:
            if not isinstance(count, int):
                return
            elif count <= 0:
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
            raise ValueError('requested passphrase length too short')
        if not self._allowed:
            raise ValueError('no allowed characters left')
        for _ in range(len(self._required), self._length):
            self._required.append(bytes(self._allowed))

    def _entropy_upper_bound(self) -> int:
        """Estimate the passphrase entropy, given the current settings.

        The entropy is the base 2 logarithm of the amount of
        possibilities.  We operate directly on the logarithms, and round
        each summand up, overestimating the true entropy.

        """
        factors: list[int] = []
        for i, charset in enumerate(self._required):
            factors.append(i + 1)
            factors.append(len(charset))
        return sum(int(math.ceil(math.log2(f))) for f in factors)

    @classmethod
    def create_hash(
        cls, phrase: bytes | bytearray, service: bytes | bytearray, *,
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
            service:
                A vault service name.  Will be suffixed with
                `Vault._UUID`, and then used as the salt value for
                PBKDF2.
            length:
                The length of the byte stream to generate.

        Returns:
            A pseudorandom byte string of length `length`.

        Note:
            Shorter values returned from this method (with the same key
            and message) are prefixes of longer values returned from
            this method.  (This property is inherited from the
            underlying PBKDF2 function.)  It is thus safe (if slow) to
            call this method with the same input with ever-increasing
            target lengths.

        Examples:
            >>> # See also Vault.phrase_from_signature examples.
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
        salt = bytes(service) + cls._UUID
        return hashlib.pbkdf2_hmac(hash_name='sha1', password=phrase,
                                   salt=salt, iterations=8, dklen=length)

    def generate(
        self, service_name: str | bytes | bytearray, /, *,
        phrase: bytes | bytearray = b'',
    ) -> bytes:
        r"""Generate a service passphrase.

        Args:
            service_name:
                The service name.
            phrase:
                If given, override the passphrase given during
                construction.

        Examples:
            >>> phrase = b'She cells C shells bye the sea shoars'
            >>> # Using default options in constructor.
            >>> Vault(phrase=phrase).generate(b'google')
            b': 4TVH#5:aZl8LueOT\\{'
            >>> # Also possible:
            >>> Vault().generate(b'google', phrase=phrase)
            b': 4TVH#5:aZl8LueOT\\{'

        """
        entropy_bound = self._entropy_upper_bound()
        # Use a safety factor, because a sequin will potentially throw
        # bits away and we cannot rely on having generated a hash of
        # exactly the right length.
        safety_factor = 2
        hash_length = int(math.ceil(safety_factor * entropy_bound / 8))
        # Ensure the phrase is a bytes object.  Needed later for safe
        # concatenation.
        if isinstance(service_name, str):
            service_name = service_name.encode('utf-8')
        elif not isinstance(service_name, bytes):
            service_name = bytes(service_name)
        assert_type(service_name, bytes)
        if not phrase:
            phrase = self._phrase
        # Repeat the passphrase generation with ever-increasing hash
        # lengths, until the passphrase can be formed without exhausting
        # the sequin.  See the guarantee in the create_hash method for
        # why this works.
        while True:
            try:
                required = self._required[:]
                seq = sequin.Sequin(self.create_hash(
                    phrase=phrase, service=service_name, length=hash_length))
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
                            charset = self._subtract(bytes(result[-1:]),
                                                     charset)
                    pos = seq.generate(len(charset))
                    result.extend(charset[pos:pos+1])
            except sequin.SequinExhaustedException:  # pragma: no cover
                hash_length *= 2
            else:
                return bytes(result)

    @classmethod
    def phrase_from_signature(
        cls, key: bytes | bytearray, /
    ) -> bytes | bytearray:
        """Obtain the master passphrase from a configured SSH key.

        vault allows the usage of certain SSH keys to derive a master
        passphrase, by signing the vault UUID with the SSH key.  The key
        type must ensure that signatures are deterministic.

        Args:
            key: The (public) SSH key to use for signing.

        Returns:
            The signature of the vault UUID under this key.

        Raises:
            ValueError:
                The SSH key is principally unsuitable for this use case.
                Usually this means that the signature is not
                deterministic.

        Examples:
            >>> # Actual test public key.
            >>> public_key = bytes.fromhex('''
            ... 00 00 00 0b 73 73 68 2d 65 64 32 35 35 31 39
            ... 00 00 00 20
            ... 81 78 81 68 26 d6 02 48 5f 0f ff 32 48 6f e4 c1
            ... 30 89 dc 1c 6a 45 06 09 e9 09 0f fb c2 12 69 76
            ... ''')
            >>> expected_sig = bytes.fromhex('''
            ... 00 00 00 0b 73 73 68 2d 65 64 32 35 35 31 39
            ... 00 00 00 40
            ... f0 98 19 80 6c 1a 97 d5 26 03 6e cc e3 65 8f 86
            ... 66 07 13 19 13 09 21 33 33 f9 e4 36 53 1d af fd
            ... 0d 08 1f ec f8 73 9b 8c 5f 55 39 16 7c 53 54 2c
            ... 1e 52 bb 30 ed 7f 89 e2 2f 69 51 55 d8 9e a6 02
            ... ''')
            >>> Vault.phrase_from_signature(public_key) == expected_sig  # doctest:+SKIP
            True

        """
        deterministic_signature_types = {
            'ssh-ed25519':
                lambda k: k.startswith(b'\x00\x00\x00\x0bssh-ed25519'),
            'ssh-ed448':
                lambda k: k.startswith(b'\x00\x00\x00\x09ssh-ed448'),
            'ssh-rsa':
                lambda k: k.startswith(b'\x00\x00\x00\x07ssh-rsa'),
        }
        if not any(v(key) for v in deterministic_signature_types.values()):
            raise ValueError(
                'unsuitable SSH key: bad key, or signature not deterministic')
        with ssh_agent_client.SSHAgentClient() as client:
            ret = client.sign(key, cls._UUID)
        return ret

    @staticmethod
    def _subtract(
        charset: bytes | bytearray, allowed: bytes | bytearray,
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
        allowed = (allowed if isinstance(allowed, bytearray)
                   else bytearray(allowed))
        assert_type(allowed, bytearray)
        if len(frozenset(allowed)) != len(allowed):
            raise ValueError('duplicate characters in set')
        if len(frozenset(charset)) != len(charset):
            raise ValueError('duplicate characters in set')
        for c in charset:
            try:
                pos = allowed.index(c)
            except ValueError:
                pass
            else:
                allowed[pos:pos+1] = []
        return allowed
