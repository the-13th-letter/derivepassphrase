# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Exporter for the vault native configuration format (v0.2 or v0.3).

The vault native formats are the configuration formats used by vault
v0.2 and v0.3.  The configuration is stored as a single encrypted file,
which is encrypted and authenticated.  v0.2 and v0.3 differ in some
details concerning key derivation and expected format of internal
structures, so they are *not* compatible.  v0.2 additionally contains
cryptographic weaknesses (API misuse of a key derivation function, and
a low-entropy method of generating initialization vectors for CBC block
encryption mode) and should thus be avoided if possible.

The public interface is the [`export_vault_native_data`][] function.
Multiple *non-public* classes are additionally documented here for
didactical and educational reasons, but they are not part of the module
API, are subject to change without notice (including removal), and
should *not* be used or relied on.

"""

# ruff: noqa: S303

from __future__ import annotations

import abc
import base64
import importlib
import json
import logging
import os
import pathlib
import warnings
from typing import TYPE_CHECKING

from derivepassphrase import _cli_msg as _msg
from derivepassphrase import exporter, vault

if TYPE_CHECKING:
    from typing import Any

    from typing_extensions import Buffer

if TYPE_CHECKING:
    from cryptography import exceptions as crypt_exceptions
    from cryptography import utils as crypt_utils
    from cryptography.hazmat.primitives import ciphers, hashes, hmac, padding
    from cryptography.hazmat.primitives.ciphers import algorithms, modes
    from cryptography.hazmat.primitives.kdf import pbkdf2
else:
    try:
        importlib.import_module('cryptography')
    except ModuleNotFoundError as exc:

        class _DummyModule:  # pragma: no cover
            def __init__(self, exc: type[Exception]) -> None:
                self.exc = exc

            def __getattr__(self, name: str) -> Any:  # noqa: ANN401
                def func(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401,ARG001
                    raise self.exc

                return func

        crypt_exceptions = crypt_utils = _DummyModule(exc)
        ciphers = hashes = hmac = padding = _DummyModule(exc)
        algorithms = modes = pbkdf2 = _DummyModule(exc)
        STUBBED = True
    else:
        from cryptography import exceptions as crypt_exceptions
        from cryptography import utils as crypt_utils
        from cryptography.hazmat.primitives import (
            ciphers,
            hashes,
            hmac,
            padding,
        )
        from cryptography.hazmat.primitives.ciphers import algorithms, modes
        from cryptography.hazmat.primitives.kdf import pbkdf2

        STUBBED = False

__all__ = ('export_vault_native_data',)

logger = logging.getLogger(__name__)


@exporter.register_export_vault_config_data_handler('v0.2', 'v0.3')
def export_vault_native_data(  # noqa: D417
    path: str | bytes | os.PathLike | None = None,
    key: str | Buffer | None = None,
    *,
    format: str,  # noqa: A002
) -> Any:  # noqa: ANN401
    """Export the full configuration stored in vault native format.

    See [`exporter.ExportVaultConfigDataFunction`][] for an explanation
    of the call signature, and the exceptions to expect.

    Other Args:
        format:
            The only supported formats are `v0.2` and `v0.3`.

    """  # noqa: DOC201,DOC501
    # Trigger import errors if necessary.
    importlib.import_module('cryptography')
    if path is None:
        path = exporter.get_vault_path()
    else:
        path = pathlib.Path(os.fsdecode(path))
    with path.open('rb') as infile:
        contents = base64.standard_b64decode(infile.read())
    if key is None:
        key = exporter.get_vault_key()
    parser_class: type[VaultNativeConfigParser] | None = {
        'v0.2': VaultNativeV02ConfigParser,
        'v0.3': VaultNativeV03ConfigParser,
    }.get(format)
    if parser_class is None:  # pragma: no cover
        msg = exporter.INVALID_VAULT_NATIVE_CONFIGURATION_FORMAT.format(
            fmt=format
        )
        raise ValueError(msg)
    try:
        return parser_class(contents, key)()
    except ValueError as exc:
        raise exporter.NotAVaultConfigError(path, format=format) from exc


def _h(bs: Buffer) -> str:
    return '<{}>'.format(memoryview(bs).hex(' '))


class VaultNativeConfigParser(abc.ABC):
    """A base parser for vault's native configuration format.

    Certain details are specific to the respective vault versions, and
    are abstracted out.  This class by itself is not instantiable
    because of this.

    """

    def __init__(self, contents: Buffer, password: str | Buffer) -> None:
        """Initialize the parser.

        Args:
            contents:
                The binary contents of the encrypted configuration file.

                Note: On disk, these are usually stored in
                base64-encoded form, not in the "raw" form as needed
                here.

            password:
                The vault master key/master passphrase the file is
                encrypted with.  Must be non-empty.  See
                [`exporter.get_vault_key`][] for details.

                If this is a text string, then the UTF-8 encoding of the
                string is used as the binary password.

        Raises:
            ValueError:
                The password must not be empty.

        Warning:
            Non-public class, provided for didactical and educational
            purposes only. Subject to change without notice, including
            removal.

        """
        if not password:
            msg = 'Password must not be empty'
            raise ValueError(msg)
        self._contents = bytes(contents)
        self._iv_size = 0
        self._mac_size = 0
        self._encryption_key = b''
        self._encryption_key_size = 0
        self._signing_key = b''
        self._signing_key_size = 0
        self._message = b''
        self._message_tag = b''
        self._iv = b''
        self._payload = b''
        self._password = password
        self._sentinel: object = object()
        self._data: Any = self._sentinel

    def __call__(self) -> Any:  # noqa: ANN401
        """Return the decrypted and parsed vault configuration.

        Raises:
            cryptography.exceptions.InvalidSignature:
                The encrypted configuration does not contain a valid
                signature.
            ValueError:
                The format is invalid, in a non-cryptographic way.  (For
                example, it contains an unsupported version marker, or
                unexpected extra contents, or invalid padding.)

        """
        if self._data is self._sentinel:
            self._parse_contents()
            self._derive_keys()
            self._check_signature()
            self._data = self._decrypt_payload()
        return self._data

    @staticmethod
    def _pbkdf2(
        password: str | Buffer, key_size: int, iterations: int
    ) -> bytes:
        """Generate a key from a password.

        Uses PBKDF2 with HMAC-SHA1, with [vault.Vault.UUID][] as a fixed
        salt value.

        Args:
            password:
                The password from which to derive the key.
            key_size:
                The size of the output string.  The effective key size
                (in bytes) is thus half of this output string size.
            iterations:
                The PBKDF2 iteration count.

        Returns:
            The PBKDF2-derived key, encoded as a lowercase ASCII
            hexadecimal string.

        Danger: Insecure use of cryptography
            This function is insecure because it uses a fixed salt
            value, which is not secure against rainbow tables.  It is
            further difficult to use because the effective key size is
            only half as large as the "size" parameter (output string
            size).  Finally, though the use of SHA-1 in HMAC per se is
            not known to be insecure, SHA-1 is known not to be
            collision-resistant.

        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        raw_key = pbkdf2.PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=key_size // 2,
            salt=vault.Vault.UUID,
            iterations=iterations,
        ).derive(bytes(password))
        result_key = raw_key.hex().lower().encode('ASCII')
        logger.debug(
            _msg.TranslatedString(
                _msg.DebugMsgTemplate.VAULT_NATIVE_PBKDF2_CALL,
                password=password,
                salt=vault.Vault.UUID,
                iterations=iterations,
                key_size=key_size // 2,
                algorithm='sha1',
                raw_result=raw_key,
                result_key=result_key.decode('ASCII'),
            ),
        )
        return result_key

    def _parse_contents(self) -> None:
        """Parse the contents into IV, payload and MAC.

        This operates on, and sets, multiple internal attributes of the
        parser.

        Raises:
            ValueError:
                The configuration file contents are clearly truncated.

        """
        logger.info(
            _msg.TranslatedString(
                _msg.InfoMsgTemplate.VAULT_NATIVE_PARSING_IV_PAYLOAD_MAC,
            ),
        )

        if len(self._contents) < self._iv_size + 16 + self._mac_size:
            msg = 'Invalid vault configuration file: file is truncated'
            raise ValueError(msg)

        def cut(buffer: bytes, cutpoint: int) -> tuple[bytes, bytes]:
            return buffer[:cutpoint], buffer[cutpoint:]

        cutpos1 = len(self._contents) - self._mac_size
        cutpos2 = self._iv_size

        self._message, self._message_tag = cut(self._contents, cutpos1)
        self._iv, self._payload = cut(self._message, cutpos2)

        logger.debug(
            _msg.TranslatedString(
                _msg.DebugMsgTemplate.VAULT_NATIVE_PARSE_BUFFER,
                contents=_h(self._contents),
                iv=_h(self._iv),
                payload=_h(self._payload),
                mac=_h(self._message_tag),
            ),
        )

    def _derive_keys(self) -> None:
        """Derive the signing and encryption keys.

        This is a bookkeeping method.  The actual work is done in
        [`_generate_keys`][].

        """
        logger.info(
            _msg.TranslatedString(
                _msg.InfoMsgTemplate.VAULT_NATIVE_DERIVING_KEYS,
            ),
        )
        self._generate_keys()
        assert len(self._encryption_key) == self._encryption_key_size, (
            'Derived encryption key is invalid'
        )
        assert len(self._signing_key) == self._signing_key_size, (
            'Derived signing key is invalid'
        )

    @abc.abstractmethod
    def _generate_keys(self) -> None:
        """Derive the signing and encryption keys, and set the key sizes.

        Subclasses must override this, as the derivation system is
        version-specific.  The default implementation raises an error.

        Raises:
            AssertionError:
                There is no default implementation.

        """
        raise AssertionError

    def _check_signature(self) -> None:
        """Check for a valid MAC on the encrypted vault configuration.

        The MAC uses HMAC-SHA1, and thus is 32 bytes long, before
        encoding.

        Raises:
            ValueError:
                The MAC is invalid.

        """
        logger.info(
            _msg.TranslatedString(
                _msg.InfoMsgTemplate.VAULT_NATIVE_CHECKING_MAC,
            ),
        )
        mac = hmac.HMAC(self._signing_key, hashes.SHA256())
        mac_input = self._hmac_input()
        logger.debug(
            _msg.TranslatedString(
                _msg.DebugMsgTemplate.VAULT_NATIVE_CHECKING_MAC_DETAILS,
                mac_input=_h(mac_input),
                mac=_h(self._message_tag),
            ),
        )
        mac.update(mac_input)
        try:
            mac.verify(self._message_tag)
        except crypt_exceptions.InvalidSignature:
            msg = 'File does not contain a valid signature'
            raise ValueError(msg) from None

    @abc.abstractmethod
    def _hmac_input(self) -> bytes:
        """Return the input the MAC is supposed to verify.

        Subclasses must override this, as the MAC-attested data is
        version-specific.  The default implementation raises an error.

        Raises:
            AssertionError:
                There is no default implementation.

        """
        raise AssertionError

    def _decrypt_payload(self) -> Any:  # noqa: ANN401
        """Return the decrypted vault configuration.

        Requires [`_parse_contents`][] and [`_derive_keys`][] to have
        run, and relies on [`_check_signature`][] for tampering
        detection.

        """
        logger.info(
            _msg.TranslatedString(
                _msg.InfoMsgTemplate.VAULT_NATIVE_DECRYPTING_CONTENTS,
            ),
        )
        decryptor = self._make_decryptor()
        padded_plaintext = bytearray()
        padded_plaintext.extend(decryptor.update(self._payload))
        padded_plaintext.extend(decryptor.finalize())
        logger.debug(
            _msg.TranslatedString(
                _msg.DebugMsgTemplate.VAULT_NATIVE_PADDED_PLAINTEXT,
                contents=_h(padded_plaintext),
            ),
        )
        unpadder = padding.PKCS7(self._iv_size * 8).unpadder()
        plaintext = bytearray()
        plaintext.extend(unpadder.update(padded_plaintext))
        plaintext.extend(unpadder.finalize())
        logger.debug(
            _msg.TranslatedString(
                _msg.DebugMsgTemplate.VAULT_NATIVE_PLAINTEXT,
                contents=_h(plaintext),
            ),
        )
        return json.loads(plaintext)

    @abc.abstractmethod
    def _make_decryptor(self) -> ciphers.CipherContext:
        """Return the cipher context object used for decryption.

        Subclasses must override this, as the cipher setup is
        version-specific.  The default implementation raises an error.

        Raises:
            AssertionError:
                There is no default implementation.

        """
        raise AssertionError


class VaultNativeV03ConfigParser(VaultNativeConfigParser):
    """A parser for vault's native configuration format (v0.3).

    This is the modern, pre-storeroom configuration format.

    Warning:
        Non-public class, provided for didactical and educational
        purposes only. Subject to change without notice, including
        removal.

    """

    KEY_SIZE = 32
    """
    Key size for both the encryption and the signing key, including the
    encoding as a hexadecimal string.  (The effective cryptographic
    strength is half of this value.)
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401
        super().__init__(*args, **kwargs)
        self._iv_size = 16
        self._mac_size = 32

    def _generate_keys(self) -> None:
        """Derive the signing and encryption keys, and set the key sizes.

        Version 0.3 vault configurations use a constant key size; see
        [`KEY_SIZE`][].  The encryption and signing keys differ in how
        many rounds of PBKDF2 they use (100 and 200, respectively).

        Danger: Insecure use of cryptography
            This function makes use of the insecure function
            [`VaultNativeConfigParser._pbkdf2`][], without any attempts
            at mitigating its insecurity.  It further uses `_pbkdf2`
            with the low iteration count of 100 and 200 rounds, which is
            *drastically* insufficient to defend against password
            guessing attacks using GPUs or ASICs.  We provide this
            function for the purpose of interoperability with existing
            vault installations.  Do not rely on this system to keep
            your vault configuration secure against access by even
            moderately determined attackers!

        """
        self._encryption_key = self._pbkdf2(self._password, self.KEY_SIZE, 100)
        self._signing_key = self._pbkdf2(self._password, self.KEY_SIZE, 200)
        self._encryption_key_size = self._signing_key_size = self.KEY_SIZE

    def _hmac_input(self) -> bytes:
        """Return the input the MAC is supposed to verify.

        This includes hexadecimal encoding of the message payload.

        """
        return self._message.hex().lower().encode('ASCII')

    def _make_decryptor(self) -> ciphers.CipherContext:
        """Return the cipher context object used for decryption.

        This is a standard AES256-CBC cipher context using the
        previously derived encryption key and the IV declared in the
        (MAC-verified) message payload.

        """
        return ciphers.Cipher(
            algorithms.AES256(self._encryption_key), modes.CBC(self._iv)
        ).decryptor()


class VaultNativeV02ConfigParser(VaultNativeConfigParser):
    """A parser for vault's native configuration format (v0.2).

    This is the classic configuration format.  Compared to v0.3, it
    contains an (accidental) API misuse for the generation of the master
    keys, a low-entropy method of generating initialization vectors for
    the AES-CBC encryption step, and extra layers of base64 encoding.
    Because of these significantly weakened confidentiality guarantees,
    v0.2 configurations should be upgraded to at least v0.3 as soon as
    possible.

    Warning:
        Non-public class, provided for didactical and educational
        purposes only. Subject to change without notice, including
        removal.

    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401
        super().__init__(*args, **kwargs)
        self._iv_size = 16
        self._mac_size = 64

    def _parse_contents(self) -> None:
        """Parse the contents into IV, payload and MAC.

        Like the base class implementation, this operates on, and sets,
        multiple internal attributes of the parser.  In version 0.2
        vault configurations, the payload is encoded in base64 and the
        message tag (MAC) is encoded in hexadecimal, so unlike the base
        class implementation, we additionally decode the payload and the
        MAC.

        Raises:
            ValueError:
                The configuration file contents are clearly truncated,
                or the payload or the message tag cannot be decoded
                properly.

        """
        super()._parse_contents()
        self._payload = base64.standard_b64decode(self._payload)
        self._message_tag = bytes.fromhex(self._message_tag.decode('ASCII'))
        logger.debug(
            _msg.TranslatedString(
                _msg.DebugMsgTemplate.VAULT_NATIVE_V02_PAYLOAD_MAC_POSTPROCESSING,
                payload=_h(self._payload),
                mac=_h(self._message_tag),
            ),
        )

    def _generate_keys(self) -> None:
        """Derive the signing and encryption keys, and set the key sizes.

        Version 0.2 vault configurations use 8-byte encryption keys and
        16-byte signing keys, including the hexadecimal encoding.  They
        both use 16 rounds of PBKDF2.  This is due to an oversight in
        vault, where the author mistakenly supplied the intended
        iteration count as the key size, and the key size as the
        iteration count.

        Danger: Insecure use of cryptography
            This function makes use of the insecure function
            [`VaultNativeConfigParser._pbkdf2`][], without any attempts
            at mitigating its insecurity.  It further uses `_pbkdf2`
            with the low iteration count of 16 rounds, which is
            *drastically* insufficient to defend against password
            guessing attacks using GPUs or ASICs, and generates the
            encryption key as a truncation of the signing key.  We
            provide this function for the purpose of interoperability
            with existing vault installations.  Do not rely on this
            system to keep your vault configuration secure against
            access by even moderately determined attackers!

        """
        self._encryption_key = self._pbkdf2(self._password, 8, 16)
        self._signing_key = self._pbkdf2(self._password, 16, 16)
        self._encryption_key_size = 8
        self._signing_key_size = 16

    def _hmac_input(self) -> bytes:
        """Return the input the MAC is supposed to verify.

        This includes hexadecimal encoding of the message payload.

        """
        return base64.standard_b64encode(self._message)

    @staticmethod
    def _evp_bytestokey_md5_one_iteration_no_salt(
        data: bytes, key_size: int, iv_size: int
    ) -> tuple[bytes, bytes]:
        """Reimplement OpenSSL's `EVP_BytesToKey` with fixed parameters.

        `EVP_BytesToKey` in general is a key derivation function,
        i.e., a function that derives key material from an input
        byte string.  `EVP_BytesToKey` conceptually splits the
        derived key material into an encryption key and an
        initialization vector (IV).

        Note: Algorithm description
            `EVP_BytesToKey` takes an input byte string, two output
            size (encryption key size and IV size), a message digest
            function, a salt value and an iteration count.  The
            derived key material is calculated in blocks, each of
            which is the output of (iterated application of) the
            message digest function.  The input to the message
            digest function is the concatenation of the previous
            block (if any) with the input byte string and the salt
            value (if any):

            ~~~~ python
            data = block_input = b''.join([previous_block, input_string, salt])
            for i in range(iteration_count):
                data = message_digest(data)
            block = data
            ~~~~

            We use as many blocks as are necessary to cover the
            total output byte string size.  The first few bytes
            (dictated by the encryption key size) form the
            encryption key, the other bytes (dictated by the IV
            size) form the IV.

        We implement exactly the subset of `EVP_BytesToKey` that the
        Node.js `crypto` library (v21 series and older) uses in its
        implementation of `crypto.createCipher("aes256", password)`.
        Specifically, the message digest function is fixed to MD5,
        the salt is always empty, and the iteration count is fixed
        at one.


        Returns:
            A 2-tuple containing the derived encryption key and the
            derived initialization vector.

        Danger: Insecure use of cryptography
            This function reimplements the OpenSSL function
            `EVP_BytesToKey`, which generates cryptographically weak
            keys, without any attempts at mitigating its insecurity.  We
            provide this function for the purpose of interoperability
            with existing vault installations.  Do not rely on this
            system to keep your vault configuration secure against
            access by even moderately determined attackers!

        """
        total_size = key_size + iv_size
        buffer = bytearray()
        last_block = b''
        salt = b''
        logger.debug(
            _msg.TranslatedString(
                _msg.DebugMsgTemplate.VAULT_NATIVE_EVP_BYTESTOKEY_INIT,
                data=_h(data),
                salt=_h(salt),
                key_size=key_size,
                iv_size=iv_size,
                buffer_length=len(buffer),
                buffer=_h(buffer),
            ),
        )
        while len(buffer) < total_size:
            with warnings.catch_warnings():
                warnings.simplefilter(
                    'ignore', crypt_utils.CryptographyDeprecationWarning
                )
                block = hashes.Hash(hashes.MD5())
            block.update(last_block)
            block.update(data)
            block.update(salt)
            last_block = block.finalize()
            buffer.extend(last_block)
            logger.debug(
                _msg.TranslatedString(
                    _msg.DebugMsgTemplate.VAULT_NATIVE_EVP_BYTESTOKEY_ROUND,
                    buffer_length=len(buffer),
                    buffer=_h(buffer),
                ),
            )
        logger.debug(
            _msg.TranslatedString(
                _msg.DebugMsgTemplate.VAULT_NATIVE_EVP_BYTESTOKEY_RESULT,
                enc_key=_h(buffer[:key_size]),
                iv=_h(buffer[key_size:total_size]),
            ),
        )
        return bytes(buffer[:key_size]), bytes(buffer[key_size:total_size])

    def _make_decryptor(self) -> ciphers.CipherContext:
        """Return the cipher context object used for decryption.

        This is a standard AES256-CBC cipher context. The encryption key
        and the IV are derived via the OpenSSL `EVP_BytesToKey` function
        (using MD5, no salt, and one iteration).  This is what the
        Node.js `crypto` library (v21 series and older) used in its
        implementation of `crypto.createCipher("aes256", password)`.

        Danger: Insecure use of cryptography
            This function makes use of (an implementation of) the
            OpenSSL function `EVP_BytesToKey`, which generates
            cryptographically weak keys, without any attempts at
            mitigating its insecurity.  We provide this function for the
            purpose of interoperability with existing vault
            installations.  Do not rely on this system to keep your
            vault configuration secure against access by even moderately
            determined attackers!

        """
        data = base64.standard_b64encode(self._iv + self._encryption_key)
        encryption_key, iv = self._evp_bytestokey_md5_one_iteration_no_salt(
            data, key_size=32, iv_size=16
        )
        return ciphers.Cipher(
            algorithms.AES256(encryption_key), modes.CBC(iv)
        ).decryptor()


if __name__ == '__main__':
    import os

    logging.basicConfig(level=('DEBUG' if os.getenv('DEBUG') else 'WARNING'))
    with exporter.get_vault_path().open('rb') as infile:
        contents = base64.standard_b64decode(infile.read())
    password = exporter.get_vault_key()
    try:
        config = VaultNativeV03ConfigParser(contents, password)()
    except ValueError:
        config = VaultNativeV02ConfigParser(contents, password)()
    print(json.dumps(config, indent=2, sort_keys=True))  # noqa: T201
