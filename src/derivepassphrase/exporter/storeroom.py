#!/usr/bin/python3

import base64
import glob
import json
import logging
import os
import os.path
import struct
from typing import TypedDict

from cryptography.hazmat.primitives import ciphers, hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.kdf import pbkdf2

STOREROOM_MASTER_KEYS_UUID = b'35b7c7ed-f71e-4adf-9051-02fb0f1e0e17'
VAULT_CIPHER_UUID = b'73e69e8a-cb05-4b50-9f42-59d76a511299'
IV_SIZE = 16
KEY_SIZE = MAC_SIZE = 32
ENCRYPTED_KEYPAIR_SIZE = 128
VERSION_SIZE = 1
MASTER_KEYS_KEY = (
    os.getenv('VAULT_KEY')
    or os.getenv('LOGNAME')
    or os.getenv('USER')
    or os.getenv('USERNAME')
)

logging.basicConfig(level=('DEBUG' if os.getenv('DEBUG') else 'WARNING'))
logger = logging.getLogger('derivepassphrase.exporter.vault_storeroom')


class KeyPair(TypedDict):
    encryption_key: bytes
    signing_key: bytes


class MasterKeys(TypedDict):
    hashing_key: bytes
    encryption_key: bytes
    signing_key: bytes


def derive_master_keys_keys(password: str | bytes, iterations: int) -> KeyPair:
    if isinstance(password, str):
        password = password.encode('ASCII')
    master_keys_keys_blob = pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA1(),  # noqa: S303
        length=64,
        salt=STOREROOM_MASTER_KEYS_UUID,
        iterations=iterations,
    ).derive(password)
    encryption_key, signing_key = struct.unpack(
        f'{KEY_SIZE}s {KEY_SIZE}s', master_keys_keys_blob
    )
    logger.debug(
        (
            'derived master_keys_keys bytes.fromhex(%s) (encryption) '
            'and bytes.fromhex(%s) (signing) '
            'from password bytes.fromhex(%s), '
            'using call '
            'pbkdf2(algorithm=%s, length=%d, salt=%s, iterations=%d)'
        ),
        repr(encryption_key.hex(' ')),
        repr(signing_key.hex(' ')),
        repr(password.hex(' ')),
        repr('SHA256'),
        64,
        repr(STOREROOM_MASTER_KEYS_UUID),
        iterations,
    )
    return {
        'encryption_key': encryption_key,
        'signing_key': signing_key,
    }


def decrypt_master_keys_data(data: bytes, keys: KeyPair) -> MasterKeys:
    ciphertext, claimed_mac = struct.unpack(
        f'{len(data) - MAC_SIZE}s {MAC_SIZE}s', data
    )
    actual_mac = hmac.HMAC(keys['signing_key'], hashes.SHA256())
    actual_mac.update(ciphertext)
    logger.debug(
        (
            'master_keys_data mac_key = bytes.fromhex(%s), '
            'hashed_content = bytes.fromhex(%s), '
            'claimed_mac = bytes.fromhex(%s), '
            'actual_mac = bytes.fromhex(%s)'
        ),
        repr(keys['signing_key'].hex(' ')),
        repr(ciphertext.hex(' ')),
        repr(claimed_mac.hex(' ')),
        repr(actual_mac.copy().finalize().hex(' ')),
    )
    actual_mac.verify(claimed_mac)

    iv, payload = struct.unpack(
        f'{IV_SIZE}s {len(ciphertext) - IV_SIZE}s', ciphertext
    )
    decryptor = ciphers.Cipher(
        algorithms.AES256(keys['encryption_key']), modes.CBC(iv)
    ).decryptor()
    padded_plaintext = bytearray()
    padded_plaintext.extend(decryptor.update(payload))
    padded_plaintext.extend(decryptor.finalize())
    unpadder = padding.PKCS7(IV_SIZE * 8).unpadder()
    plaintext = bytearray()
    plaintext.extend(unpadder.update(padded_plaintext))
    plaintext.extend(unpadder.finalize())
    if len(plaintext) != 3 * KEY_SIZE:
        msg = (
            f'Expecting 3 encrypted keys at {3 * KEY_SIZE} bytes total, '
            f'but found {len(plaintext)} instead'
        )
        raise RuntimeError(msg)
    hashing_key, encryption_key, signing_key = struct.unpack(
        f'{KEY_SIZE}s {KEY_SIZE}s {KEY_SIZE}s', plaintext
    )
    return {
        'hashing_key': hashing_key,
        'encryption_key': encryption_key,
        'signing_key': signing_key,
    }


def decrypt_session_keys(data: bytes, keys: MasterKeys) -> KeyPair:
    ciphertext, claimed_mac = struct.unpack(
        f'{len(data) - MAC_SIZE}s {MAC_SIZE}s', data
    )
    actual_mac = hmac.HMAC(keys['signing_key'], hashes.SHA256())
    actual_mac.update(ciphertext)
    logger.debug(
        (
            'decrypt_bucket_line (session_keys): '
            'mac_key = bytes.fromhex(%s) (master), '
            'hashed_content = bytes.fromhex(%s), '
            'claimed_mac = bytes.fromhex(%s), '
            'actual_mac = bytes.fromhex(%s)'
        ),
        repr(keys['signing_key'].hex(' ')),
        repr(ciphertext.hex(' ')),
        repr(claimed_mac.hex(' ')),
        repr(actual_mac.copy().finalize().hex(' ')),
    )
    actual_mac.verify(claimed_mac)

    iv, payload = struct.unpack(
        f'{IV_SIZE}s {len(ciphertext) - IV_SIZE}s', ciphertext
    )
    decryptor = ciphers.Cipher(
        algorithms.AES256(keys['encryption_key']), modes.CBC(iv)
    ).decryptor()
    padded_plaintext = bytearray()
    padded_plaintext.extend(decryptor.update(payload))
    padded_plaintext.extend(decryptor.finalize())
    unpadder = padding.PKCS7(IV_SIZE * 8).unpadder()
    plaintext = bytearray()
    plaintext.extend(unpadder.update(padded_plaintext))
    plaintext.extend(unpadder.finalize())

    session_encryption_key, session_signing_key, inner_payload = struct.unpack(
        f'{KEY_SIZE}s {KEY_SIZE}s {len(plaintext) - 2 * KEY_SIZE}s',
        plaintext,
    )
    session_keys: KeyPair = {
        'encryption_key': session_encryption_key,
        'signing_key': session_signing_key,
    }

    logger.debug(
        (
            'decrypt_bucket_line (session_keys): '
            'decrypt_aes256_cbc_and_unpad(key=bytes.fromhex(%s), '
            'iv=bytes.fromhex(%s))(bytes.fromhex(%s)) '
            '= bytes.fromhex(%s) '
            '= {"encryption_key": bytes.fromhex(%s), '
            '"signing_key": bytes.fromhex(%s)}'
        ),
        repr(keys['encryption_key'].hex(' ')),
        repr(iv.hex(' ')),
        repr(payload.hex(' ')),
        repr(plaintext.hex(' ')),
        repr(session_keys['encryption_key'].hex(' ')),
        repr(session_keys['signing_key'].hex(' ')),
    )

    if inner_payload:
        logger.debug(
            'ignoring misplaced inner payload bytes.fromhex(%s)',
            repr(inner_payload.hex(' ')),
        )

    return session_keys


def decrypt_contents(data: bytes, keys: KeyPair) -> bytes:
    ciphertext, claimed_mac = struct.unpack(
        f'{len(data) - MAC_SIZE}s {MAC_SIZE}s', data
    )
    actual_mac = hmac.HMAC(keys['signing_key'], hashes.SHA256())
    actual_mac.update(ciphertext)
    logger.debug(
        (
            'decrypt_bucket_line (contents): '
            'mac_key = bytes.fromhex(%s), '
            'hashed_content = bytes.fromhex(%s), '
            'claimed_mac = bytes.fromhex(%s), '
            'actual_mac = bytes.fromhex(%s)'
        ),
        repr(keys['signing_key'].hex(' ')),
        repr(ciphertext.hex(' ')),
        repr(claimed_mac.hex(' ')),
        repr(actual_mac.copy().finalize().hex(' ')),
    )
    actual_mac.verify(claimed_mac)

    iv, payload = struct.unpack(
        f'{IV_SIZE}s {len(ciphertext) - IV_SIZE}s', ciphertext
    )
    decryptor = ciphers.Cipher(
        algorithms.AES256(keys['encryption_key']), modes.CBC(iv)
    ).decryptor()
    padded_plaintext = bytearray()
    padded_plaintext.extend(decryptor.update(payload))
    padded_plaintext.extend(decryptor.finalize())
    unpadder = padding.PKCS7(IV_SIZE * 8).unpadder()
    plaintext = bytearray()
    plaintext.extend(unpadder.update(padded_plaintext))
    plaintext.extend(unpadder.finalize())

    logger.debug(
        (
            'decrypt_bucket_line (contents): '
            'decrypt_aes256_cbc_and_unpad(key=bytes.fromhex(%s), '
            'iv=bytes.fromhex(%s))(bytes.fromhex(%s)) '
            '= bytes.fromhex(%s)'
        ),
        repr(keys['encryption_key'].hex(' ')),
        repr(iv.hex(' ')),
        repr(payload.hex(' ')),
        repr(plaintext.hex(' ')),
    )

    return plaintext


def decrypt_bucket_line(bucket_line: bytes, master_keys: MasterKeys) -> bytes:
    logger.debug(
        (
            'decrypt_bucket_line: data = bytes.fromhex(%s), '
            'encryption_key = bytes.fromhex(%s), '
            'signing_key = bytes.fromhex(%s)'
        ),
        repr(bucket_line.hex(' ')),
        repr(master_keys['encryption_key'].hex(' ')),
        repr(master_keys['signing_key'].hex(' ')),
    )
    data_version, encrypted_session_keys, data_contents = struct.unpack(
        (
            f'B {ENCRYPTED_KEYPAIR_SIZE}s '
            f'{len(bucket_line) - 1 - ENCRYPTED_KEYPAIR_SIZE}s'
        ),
        bucket_line,
    )
    if data_version != 1:
        msg = f'Cannot handle version {data_version} encrypted data'
        raise RuntimeError(msg)
    session_keys = decrypt_session_keys(encrypted_session_keys, master_keys)
    return decrypt_contents(data_contents, session_keys)


def decrypt_bucket_file(filename: str, master_keys: MasterKeys) -> None:
    with (
        open(filename, 'rb') as bucket_file,
        open(filename + '.decrypted', 'wb') as decrypted_file,
    ):
        header_line = bucket_file.readline()
        try:
            header = json.loads(header_line)
        except ValueError as exc:
            msg = f'Invalid bucket file: {filename}'
            raise RuntimeError(msg) from exc
        if header != {'version': 1}:
            msg = f'Invalid bucket file: {filename}'
            raise RuntimeError(msg) from None
        decrypted_file.write(header_line)
        for line in bucket_file:
            decrypted_contents = (
                decrypt_bucket_line(
                    base64.standard_b64decode(line), master_keys
                ).removesuffix(b'\n')
                + b'\n'
            )
            decrypted_file.write(decrypted_contents)


def main() -> None:
    with open('.keys', encoding='utf-8') as master_keys_file:
        header = json.loads(master_keys_file.readline())
        if header != {'version': 1}:
            msg = 'bad or unsupported keys version header'
            raise RuntimeError(msg)
        raw_keys_data = base64.standard_b64decode(master_keys_file.readline())
        encrypted_keys_params, encrypted_keys = struct.unpack(
            f'B {len(raw_keys_data) - 1}s', raw_keys_data
        )
        if master_keys_file.read():
            msg = 'trailing data; cannot make sense of .keys file'
            raise RuntimeError(msg)
    encrypted_keys_version = encrypted_keys_params >> 4
    if encrypted_keys_version != 1:
        msg = f'cannot handle version {encrypted_keys_version} encrypted keys'
        raise RuntimeError(msg)
    encrypted_keys_iterations = 2 ** (10 + (encrypted_keys_params & 0x0F))
    master_keys_keys = derive_master_keys_keys(
        MASTER_KEYS_KEY, encrypted_keys_iterations
    )
    master_keys = decrypt_master_keys_data(encrypted_keys, master_keys_keys)

    for file in glob.glob('[01][0-9a-f]'):
        decrypt_bucket_file(file, master_keys)


if __name__ == '__main__':
    main()
