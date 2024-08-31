#!/usr/bin/python3

from __future__ import annotations

import abc
import base64
import json
import logging
import warnings
from typing import TYPE_CHECKING

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
    except ModuleNotFoundError as exc:

        class DummyModule:  # pragma: no cover
            def __init__(self, exc: type[Exception]) -> None:
                self.exc = exc

            def __getattr__(self, name: str) -> Any:
                def func(*args: Any, **kwargs: Any) -> Any:  # noqa: ARG001
                    raise self.exc

                return func

        crypt_exceptions = crypt_utils = DummyModule(exc)
        ciphers = hashes = hmac = padding = DummyModule(exc)
        algorithms = modes = pbkdf2 = DummyModule(exc)
        STUBBED = True
    else:
        STUBBED = False

logger = logging.getLogger(__name__)


def _h(bs: bytes | bytearray) -> str:
    return 'bytes.fromhex({!r})'.format(bs.hex(' '))


class VaultNativeConfigParser(abc.ABC):
    def __init__(self, contents: Buffer, password: str | Buffer) -> None:
        if not password:
            msg = 'Password must not be empty'
            raise ValueError(msg)
        self._contents = bytes(contents)
        self.iv_size = 0
        self.mac_size = 0
        self.encryption_key = b''
        self.encryption_key_size = 0
        self.signing_key = b''
        self.signing_key_size = 0
        self.message = b''
        self.message_tag = b''
        self.iv = b''
        self.payload = b''
        self._password = password
        self._sentinel: object = object()
        self._data: Any = self._sentinel

    def __call__(self) -> Any:
        if self._data is self._sentinel:
            self._parse_contents()
            self._derive_keys()
            self._check_signature()
            self._data = self._decrypt_payload()
        return self._data

    @staticmethod
    def pbkdf2(
        password: str | Buffer, key_size: int, iterations: int
    ) -> bytes:
        if isinstance(password, str):
            password = password.encode('utf-8')
        raw_key = pbkdf2.PBKDF2HMAC(
            algorithm=hashes.SHA1(),  # noqa: S303
            length=key_size // 2,
            salt=vault.Vault._UUID,  # noqa: SLF001
            iterations=iterations,
        ).derive(bytes(password))
        logger.debug(
            'binary = pbkdf2(%s, %s, %s, %s, %s) = %s -> %s',
            repr(password),
            repr(vault.Vault._UUID),  # noqa: SLF001
            iterations,
            key_size // 2,
            repr('sha1'),
            _h(raw_key),
            _h(raw_key.hex().lower().encode('ASCII')),
        )
        return raw_key.hex().lower().encode('ASCII')

    def _parse_contents(self) -> None:
        logger.info('Parsing IV, payload and signature from the file contents')

        if len(self._contents) < self.iv_size + 16 + self.mac_size:
            msg = 'Invalid vault configuration file: file is truncated'
            raise ValueError(msg)

        def cut(buffer: bytes, cutpoint: int) -> tuple[bytes, bytes]:
            return buffer[:cutpoint], buffer[cutpoint:]

        cutpos1 = len(self._contents) - self.mac_size
        cutpos2 = self.iv_size

        self.message, self.message_tag = cut(self._contents, cutpos1)
        self.iv, self.payload = cut(self.message, cutpos2)

        logger.debug(
            'buffer %s = [[%s, %s], %s]',
            _h(self._contents),
            _h(self.iv),
            _h(self.payload),
            _h(self.message_tag),
        )

    def _derive_keys(self) -> None:
        logger.info('Deriving an encryption and signing key')
        self._generate_keys()
        assert (
            len(self.encryption_key) == self.encryption_key_size
        ), 'Derived encryption key is invalid'
        assert (
            len(self.signing_key) == self.signing_key_size
        ), 'Derived signing key is invalid'

    @abc.abstractmethod
    def _generate_keys(self) -> None:
        raise AssertionError

    def _check_signature(self) -> None:
        logger.info('Checking HMAC signature')
        mac = hmac.HMAC(self.signing_key, hashes.SHA256())
        mac_input = self._hmac_input()
        logger.debug(
            'mac_input = %s, expected_tag = %s',
            _h(mac_input),
            _h(self.message_tag),
        )
        mac.update(mac_input)
        try:
            mac.verify(self.message_tag)
        except crypt_exceptions.InvalidSignature:
            msg = 'File does not contain a valid signature'
            raise ValueError(msg) from None

    @abc.abstractmethod
    def _hmac_input(self) -> bytes:
        raise AssertionError

    def _decrypt_payload(self) -> Any:
        decryptor = self._make_decryptor()
        padded_plaintext = bytearray()
        padded_plaintext.extend(decryptor.update(self.payload))
        padded_plaintext.extend(decryptor.finalize())
        logger.debug('padded plaintext = %s', _h(padded_plaintext))
        unpadder = padding.PKCS7(self.iv_size * 8).unpadder()
        plaintext = bytearray()
        plaintext.extend(unpadder.update(padded_plaintext))
        plaintext.extend(unpadder.finalize())
        logger.debug('plaintext = %s', _h(plaintext))
        return json.loads(plaintext)

    @abc.abstractmethod
    def _make_decryptor(self) -> ciphers.CipherContext:
        raise AssertionError


class VaultNativeV03ConfigParser(VaultNativeConfigParser):
    KEY_SIZE = 32

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.iv_size = 16
        self.mac_size = 32

    def __call__(self) -> Any:
        if self._data is self._sentinel:
            logger.info('Attempting to parse as v0.3 configuration')
            return super().__call__()
        return self._data

    def _generate_keys(self) -> None:
        self.encryption_key = self.pbkdf2(self._password, self.KEY_SIZE, 100)
        self.signing_key = self.pbkdf2(self._password, self.KEY_SIZE, 200)
        self.encryption_key_size = self.signing_key_size = self.KEY_SIZE

    def _hmac_input(self) -> bytes:
        return self.message.hex().lower().encode('ASCII')

    def _make_decryptor(self) -> ciphers.CipherContext:
        return ciphers.Cipher(
            algorithms.AES256(self.encryption_key), modes.CBC(self.iv)
        ).decryptor()


class VaultNativeV02ConfigParser(VaultNativeConfigParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.iv_size = 16
        self.mac_size = 64

    def __call__(self) -> Any:
        if self._data is self._sentinel:
            logger.info('Attempting to parse as v0.2 configuration')
            return super().__call__()
        return self._data

    def _parse_contents(self) -> None:
        super()._parse_contents()
        logger.debug('Decoding payload (base64) and message tag (hex)')
        self.payload = base64.standard_b64decode(self.payload)
        self.message_tag = bytes.fromhex(self.message_tag.decode('ASCII'))

    def _generate_keys(self) -> None:
        self.encryption_key = self.pbkdf2(self._password, 8, 16)
        self.signing_key = self.pbkdf2(self._password, 16, 16)
        self.encryption_key_size = 8
        self.signing_key_size = 16

    def _hmac_input(self) -> bytes:
        return base64.standard_b64encode(self.message)

    def _make_decryptor(self) -> ciphers.CipherContext:
        def evp_bytestokey_md5_one_iteration_no_salt(
            data: bytes, key_size: int, iv_size: int
        ) -> tuple[bytes, bytes]:
            total_size = key_size + iv_size
            buffer = bytearray()
            last_block = b''
            salt = b''
            logging.debug(
                (
                    'data = %s, salt = %s, key_size = %s, iv_size = %s, '
                    'buffer length = %s, buffer = %s'
                ),
                _h(data),
                _h(salt),
                key_size,
                iv_size,
                len(buffer),
                _h(buffer),
            )
            while len(buffer) < total_size:
                with warnings.catch_warnings():
                    warnings.simplefilter(
                        'ignore', crypt_utils.CryptographyDeprecationWarning
                    )
                    block = hashes.Hash(hashes.MD5())  # noqa: S303
                block.update(last_block)
                block.update(data)
                block.update(salt)
                last_block = block.finalize()
                buffer.extend(last_block)
                logging.debug(
                    'buffer length = %s, buffer = %s', len(buffer), _h(buffer)
                )
            logging.debug(
                'encryption_key = %s, iv = %s',
                _h(buffer[:key_size]),
                _h(buffer[key_size:total_size]),
            )
            return bytes(buffer[:key_size]), bytes(buffer[key_size:total_size])

        data = base64.standard_b64encode(self.iv + self.encryption_key)
        encryption_key, iv = evp_bytestokey_md5_one_iteration_no_salt(
            data, key_size=32, iv_size=16
        )
        return ciphers.Cipher(
            algorithms.AES256(encryption_key), modes.CBC(iv)
        ).decryptor()


if __name__ == '__main__':
    import os

    logging.basicConfig(level=('DEBUG' if os.getenv('DEBUG') else 'WARNING'))
    with open(exporter.get_vault_path(), 'rb') as infile:
        contents = base64.standard_b64decode(infile.read())
    password = exporter.get_vault_key()
    try:
        config = VaultNativeV03ConfigParser(contents, password)()
    except ValueError:
        config = VaultNativeV02ConfigParser(contents, password)()
    print(json.dumps(config, indent=2, sort_keys=True))  # noqa: T201
