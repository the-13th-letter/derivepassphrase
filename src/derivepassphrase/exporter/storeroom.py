# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Exporter for the vault "storeroom" configuration format.

The "storeroom" format is the experimental format used in alpha and beta
versions of vault beyond v0.3.0.  The configuration is stored as
a separate directory, which acts like a hash table (i.e. has named
slots) and provides an impure quasi-filesystem interface.  Each hash
table entry is separately encrypted and authenticated.  James Coglan
designed this format to avoid concurrent write issues when updating or
synchronizing the vault configuration with e.g. a cloud service.

The public interface is the [`export_storeroom_data`][] function.
Multiple *non-public* functions are additionally documented here for
didactical and educational reasons, but they are not part of the module
API, are subject to change without notice (including removal), and
should *not* be used or relied on.

"""

from __future__ import annotations

import base64
import fnmatch
import json
import logging
import os
import os.path
import struct
from typing import TYPE_CHECKING, Any, TypedDict

from derivepassphrase import exporter

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cryptography.hazmat.primitives import ciphers, hashes, hmac, padding
    from cryptography.hazmat.primitives.ciphers import algorithms, modes
    from cryptography.hazmat.primitives.kdf import pbkdf2
else:
    try:
        from cryptography.hazmat.primitives import (
            ciphers,
            hashes,
            hmac,
            padding,
        )
        from cryptography.hazmat.primitives.ciphers import algorithms, modes
        from cryptography.hazmat.primitives.kdf import pbkdf2
    except ModuleNotFoundError as exc:

        class _DummyModule:  # pragma: no cover
            def __init__(self, exc: type[Exception]) -> None:
                self.exc = exc

            def __getattr__(self, name: str) -> Any:  # noqa: ANN401
                def func(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401,ARG001
                    raise self.exc

                return func

        ciphers = hashes = hmac = padding = _DummyModule(exc)
        algorithms = modes = pbkdf2 = _DummyModule(exc)
        STUBBED = True
    else:
        STUBBED = False

STOREROOM_MASTER_KEYS_UUID = b'35b7c7ed-f71e-4adf-9051-02fb0f1e0e17'
VAULT_CIPHER_UUID = b'73e69e8a-cb05-4b50-9f42-59d76a511299'
IV_SIZE = 16
KEY_SIZE = MAC_SIZE = 32
ENCRYPTED_KEYPAIR_SIZE = 128
VERSION_SIZE = 1

__all__ = ('export_storeroom_data',)

logger = logging.getLogger(__name__)


class KeyPair(TypedDict):
    """A pair of AES256 keys, one for encryption and one for signing.

    Attributes:
        encryption_key:
            AES256 key, used for encryption with AES256-CBC (with PKCS#7
            padding).
        signing_key:
            AES256 key, used for signing with HMAC-SHA256.

    """

    encryption_key: bytes
    """"""
    signing_key: bytes
    """"""


class MasterKeys(TypedDict):
    """A triple of AES256 keys, for encryption, signing and hashing.

    Attributes:
        hashing_key:
            AES256 key, used for hashing with HMAC-SHA256 to derive
            a hash table slot for an item.
        encryption_key:
            AES256 key, used for encryption with AES256-CBC (with PKCS#7
            padding).
        signing_key:
            AES256 key, used for signing with HMAC-SHA256.

    """

    hashing_key: bytes
    """"""
    encryption_key: bytes
    """"""
    signing_key: bytes
    """"""


def derive_master_keys_keys(password: str | bytes, iterations: int) -> KeyPair:
    """Derive encryption and signing keys for the master keys data.

    The master password is run through a key derivation function to
    obtain a 64-byte string, which is then split to yield two 32-byte
    keys.  The key derivation function is PBKDF2, using HMAC-SHA1 and
    salted with the storeroom master keys UUID.

    Args:
        password:
            A master password for the storeroom instance.  Usually read
            from the `VAULT_KEY` environment variable, otherwise
            defaults to the username.
        iterations:
            A count of rounds for the underlying key derivation
            function.  Usually stored as a setting next to the encrypted
            master keys data.

    Returns:
        A 2-tuple of keys, the encryption key and the signing key, to
        decrypt and verify the master keys data with.

    Warning:
        Non-public function, provided for didactical and educational
        purposes only.  Subject to change without notice, including
        removal.

    """
    if isinstance(password, str):
        password = password.encode('ASCII')
    master_keys_keys_blob = pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=2 * KEY_SIZE,
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
    r"""Decrypt the master keys data.

    The master keys data contains:

    - a 16-byte IV,
    - a 96-byte AES256-CBC-encrypted payload, plus 16 further bytes of
      PKCS7 padding, and
    - a 32-byte MAC of the preceding 128 bytes.

    The decrypted payload itself consists of three 32-byte keys: the
    hashing, encryption and signing keys, in that order.

    The encrypted payload is encrypted with the encryption key, and the
    MAC is created based on the signing key.  As per standard
    cryptographic procedure, the MAC can be verified before attempting
    to decrypt the payload.

    Because the payload size is both fixed and a multiple of the cipher
    blocksize, in this case, the PKCS7 padding always is `b'\x10' * 16`.

    Args:
        data:
            The encrypted master keys data.
        keys:
            The encryption and signing keys for the master keys data.
            These should have previously been derived via the
            [`derive_master_keys_keys`][] function.

    Returns:
        The master encryption, signing and hashing keys.

    Raises:
        cryptography.exceptions.InvalidSignature:
            The data does not contain a valid signature under the given
            key.
        ValueError:
            The format is invalid, in a non-cryptographic way.  (For
            example, it contains an unsupported version marker, or
            unexpected extra contents, or invalid padding.)

    Warning:
        Non-public function, provided for didactical and educational
        purposes only.  Subject to change without notice, including
        removal.

    """
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

    try:
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
        hashing_key, encryption_key, signing_key = struct.unpack(
            f'{KEY_SIZE}s {KEY_SIZE}s {KEY_SIZE}s', plaintext
        )
    except (ValueError, struct.error) as exc:
        msg = 'Invalid encrypted master keys payload'
        raise ValueError(msg) from exc
    return {
        'hashing_key': hashing_key,
        'encryption_key': encryption_key,
        'signing_key': signing_key,
    }


def decrypt_session_keys(data: bytes, master_keys: MasterKeys) -> KeyPair:
    r"""Decrypt the bucket item's session keys.

    The bucket item's session keys are single-use keys for encrypting
    and signing a single item in the storage bucket.  The encrypted
    session key data consists of:

    - a 16-byte IV,
    - a 64-byte AES256-CBC-encrypted payload, plus 16 further bytes of
      PKCS7 padding, and
    - a 32-byte MAC of the preceding 96 bytes.

    The encrypted payload is encrypted with the master encryption key,
    and the MAC is created with the master signing key.  As per standard
    cryptographic procedure, the MAC can be verified before attempting
    to decrypt the payload.

    Because the payload size is both fixed and a multiple of the cipher
    blocksize, in this case, the PKCS7 padding always is `b'\x10' * 16`.

    Args:
        data:
            The encrypted bucket item session key data.
        master_keys:
            The master keys.  Presumably these have previously been
            obtained via the [`decrypt_master_keys_data`][] function.

    Returns:
        The bucket item's encryption and signing keys.

    Raises:
        cryptography.exceptions.InvalidSignature:
            The data does not contain a valid signature under the given
            key.
        ValueError:
            The format is invalid, in a non-cryptographic way.  (For
            example, it contains an unsupported version marker, or
            unexpected extra contents, or invalid padding.)

    Warning:
        Non-public function, provided for didactical and educational
        purposes only.  Subject to change without notice, including
        removal.

    """
    ciphertext, claimed_mac = struct.unpack(
        f'{len(data) - MAC_SIZE}s {MAC_SIZE}s', data
    )
    actual_mac = hmac.HMAC(master_keys['signing_key'], hashes.SHA256())
    actual_mac.update(ciphertext)
    logger.debug(
        (
            'decrypt_bucket_item (session_keys): '
            'mac_key = bytes.fromhex(%s) (master), '
            'hashed_content = bytes.fromhex(%s), '
            'claimed_mac = bytes.fromhex(%s), '
            'actual_mac = bytes.fromhex(%s)'
        ),
        repr(master_keys['signing_key'].hex(' ')),
        repr(ciphertext.hex(' ')),
        repr(claimed_mac.hex(' ')),
        repr(actual_mac.copy().finalize().hex(' ')),
    )
    actual_mac.verify(claimed_mac)

    try:
        iv, payload = struct.unpack(
            f'{IV_SIZE}s {len(ciphertext) - IV_SIZE}s', ciphertext
        )
        decryptor = ciphers.Cipher(
            algorithms.AES256(master_keys['encryption_key']), modes.CBC(iv)
        ).decryptor()
        padded_plaintext = bytearray()
        padded_plaintext.extend(decryptor.update(payload))
        padded_plaintext.extend(decryptor.finalize())
        unpadder = padding.PKCS7(IV_SIZE * 8).unpadder()
        plaintext = bytearray()
        plaintext.extend(unpadder.update(padded_plaintext))
        plaintext.extend(unpadder.finalize())
        session_encryption_key, session_signing_key = struct.unpack(
            f'{KEY_SIZE}s {KEY_SIZE}s', plaintext
        )
    except (ValueError, struct.error) as exc:
        msg = 'Invalid encrypted session keys payload'
        raise ValueError(msg) from exc

    session_keys: KeyPair = {
        'encryption_key': session_encryption_key,
        'signing_key': session_signing_key,
    }

    logger.debug(
        (
            'decrypt_bucket_item (session_keys): '
            'decrypt_aes256_cbc_and_unpad(key=bytes.fromhex(%s), '
            'iv=bytes.fromhex(%s))(bytes.fromhex(%s)) '
            '= bytes.fromhex(%s) '
            '= {"encryption_key": bytes.fromhex(%s), '
            '"signing_key": bytes.fromhex(%s)}'
        ),
        repr(master_keys['encryption_key'].hex(' ')),
        repr(iv.hex(' ')),
        repr(payload.hex(' ')),
        repr(plaintext.hex(' ')),
        repr(session_keys['encryption_key'].hex(' ')),
        repr(session_keys['signing_key'].hex(' ')),
    )

    return session_keys


def decrypt_contents(data: bytes, session_keys: KeyPair) -> bytes:
    """Decrypt the bucket item's contents.

    The data consists of:

    - a 16-byte IV,
    - a variable-sized AES256-CBC-encrypted payload (using PKCS7 padding
      on the inside), and
    - a 32-byte MAC of the preceding bytes.

    The encrypted payload is encrypted with the bucket item's session
    encryption key, and the MAC is created with the bucket item's
    session signing key.  As per standard cryptographic procedure, the
    MAC can be verified before attempting to decrypt the payload.

    Args:
        data:
            The encrypted bucket item payload data.
        session_keys:
            The bucket item's session keys.  Presumably these have
            previously been obtained via the [`decrypt_session_keys`][]
            function.

    Returns:
        The bucket item's payload.

    Raises:
        cryptography.exceptions.InvalidSignature:
            The data does not contain a valid signature under the given
            key.
        ValueError:
            The format is invalid, in a non-cryptographic way.  (For
            example, it contains an unsupported version marker, or
            unexpected extra contents, or invalid padding.)

    Warning:
        Non-public function, provided for didactical and educational
        purposes only.  Subject to change without notice, including
        removal.

    """
    ciphertext, claimed_mac = struct.unpack(
        f'{len(data) - MAC_SIZE}s {MAC_SIZE}s', data
    )
    actual_mac = hmac.HMAC(session_keys['signing_key'], hashes.SHA256())
    actual_mac.update(ciphertext)
    logger.debug(
        (
            'decrypt_bucket_item (contents): '
            'mac_key = bytes.fromhex(%s), '
            'hashed_content = bytes.fromhex(%s), '
            'claimed_mac = bytes.fromhex(%s), '
            'actual_mac = bytes.fromhex(%s)'
        ),
        repr(session_keys['signing_key'].hex(' ')),
        repr(ciphertext.hex(' ')),
        repr(claimed_mac.hex(' ')),
        repr(actual_mac.copy().finalize().hex(' ')),
    )
    actual_mac.verify(claimed_mac)

    iv, payload = struct.unpack(
        f'{IV_SIZE}s {len(ciphertext) - IV_SIZE}s', ciphertext
    )
    decryptor = ciphers.Cipher(
        algorithms.AES256(session_keys['encryption_key']), modes.CBC(iv)
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
            'decrypt_bucket_item (contents): '
            'decrypt_aes256_cbc_and_unpad(key=bytes.fromhex(%s), '
            'iv=bytes.fromhex(%s))(bytes.fromhex(%s)) '
            '= bytes.fromhex(%s)'
        ),
        repr(session_keys['encryption_key'].hex(' ')),
        repr(iv.hex(' ')),
        repr(payload.hex(' ')),
        repr(plaintext.hex(' ')),
    )

    return plaintext


def decrypt_bucket_item(bucket_item: bytes, master_keys: MasterKeys) -> bytes:
    """Decrypt a bucket item.

    Args:
        bucket_item:
            The encrypted bucket item.
        master_keys:
            The master keys.  Presumably these have previously been
            obtained via the [`decrypt_master_keys_data`][] function.

    Returns:
        The decrypted bucket item.

    Raises:
        cryptography.exceptions.InvalidSignature:
            The data does not contain a valid signature under the given
            key.
        ValueError:
            The format is invalid, in a non-cryptographic way.  (For
            example, it contains an unsupported version marker, or
            unexpected extra contents, or invalid padding.)

    Warning:
        Non-public function, provided for didactical and educational
        purposes only.  Subject to change without notice, including
        removal.

    """
    logger.debug(
        (
            'decrypt_bucket_item: data = bytes.fromhex(%s), '
            'encryption_key = bytes.fromhex(%s), '
            'signing_key = bytes.fromhex(%s)'
        ),
        repr(bucket_item.hex(' ')),
        repr(master_keys['encryption_key'].hex(' ')),
        repr(master_keys['signing_key'].hex(' ')),
    )
    data_version, encrypted_session_keys, data_contents = struct.unpack(
        (
            f'B {ENCRYPTED_KEYPAIR_SIZE}s '
            f'{len(bucket_item) - 1 - ENCRYPTED_KEYPAIR_SIZE}s'
        ),
        bucket_item,
    )
    if data_version != 1:
        msg = f'Cannot handle version {data_version} encrypted data'
        raise ValueError(msg)
    session_keys = decrypt_session_keys(encrypted_session_keys, master_keys)
    return decrypt_contents(data_contents, session_keys)


def decrypt_bucket_file(
    filename: str,
    master_keys: MasterKeys,
    *,
    root_dir: str | bytes | os.PathLike = '.',
) -> Iterator[bytes]:
    """Decrypt a complete bucket.

    Args:
        filename:
            The bucket file's filename.
        master_keys:
            The master keys.  Presumably these have previously been
            obtained via the [`decrypt_master_keys_data`][] function.
        root_dir:
            The root directory of the data store.  The filename is
            interpreted relatively to this directory.

    Yields:
        A decrypted bucket item.

    Raises:
        cryptography.exceptions.InvalidSignature:
            The data does not contain a valid signature under the given
            key.
        ValueError:
            The format is invalid, in a non-cryptographic way.  (For
            example, it contains an unsupported version marker, or
            unexpected extra contents, or invalid padding.)

    Warning:
        Non-public function, provided for didactical and educational
        purposes only.  Subject to change without notice, including
        removal.

    """
    with open(
        os.path.join(os.fsdecode(root_dir), filename), 'rb'
    ) as bucket_file:
        header_line = bucket_file.readline()
        try:
            header = json.loads(header_line)
        except ValueError as exc:
            msg = f'Invalid bucket file: {filename}'
            raise ValueError(msg) from exc
        if header != {'version': 1}:
            msg = f'Invalid bucket file: {filename}'
            raise ValueError(msg) from None
        for line in bucket_file:
            yield decrypt_bucket_item(
                base64.standard_b64decode(line), master_keys
            )


def _store(config: dict[str, Any], path: str, json_contents: bytes) -> None:
    """Store the JSON contents at path in the config structure.

    Traverse the config structure according to path, and set the value
    of the leaf to the decoded JSON contents.

    A path `/foo/bar/xyz` translates to the JSON structure
    `{"foo": {"bar": {"xyz": ...}}}`.

    Args:
        config:
            The (top-level) configuration structure to update.
        path:
            The path within the configuration structure to traverse.
        json_contents:
            The contents to set the item to, after JSON-decoding.

    Raises:
        json.JSONDecodeError:
            There was an error parsing the JSON contents.

    """
    contents = json.loads(json_contents)
    path_parts = [part for part in path.split('/') if part]
    for part in path_parts[:-1]:
        config = config.setdefault(part, {})
    if path_parts:
        config[path_parts[-1]] = contents


def export_storeroom_data(  # noqa: C901,PLR0912,PLR0914,PLR0915
    storeroom_path: str | bytes | os.PathLike | None = None,
    master_keys_key: str | bytes | None = None,
) -> dict[str, Any]:
    """Export the full configuration stored in the storeroom.

    Args:
        storeroom_path:
            Path to the storeroom; usually `~/.vault`.  If not given,
            then query [`exporter.get_vault_path`][] for the value.
        master_keys_key:
            Encryption key/password for the master keys, usually the
            username, or passed via the `VAULT_KEY` environment
            variable.  If not given, then query
            [`exporter.get_vault_key`][] for the value.

    Returns:
        The full configuration, as stored in the storeroom.

        This may or may not be a valid configuration according to vault
        or derivepassphrase.

    Raises:
        RuntimeError:
            Something went wrong during data collection, e.g. we
            encountered unsupported or corrupted data in the storeroom.
        json.JSONDecodeError:
            An internal JSON data structure failed to parse from disk.
            The storeroom is probably corrupted.

    """
    if storeroom_path is None:
        storeroom_path = exporter.get_vault_path()
    if master_keys_key is None:
        master_keys_key = exporter.get_vault_key()
    with open(
        os.path.join(os.fsdecode(storeroom_path), '.keys'), encoding='utf-8'
    ) as master_keys_file:
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
        master_keys_key, encrypted_keys_iterations
    )
    master_keys = decrypt_master_keys_data(encrypted_keys, master_keys_keys)

    config_structure: dict[str, Any] = {}
    json_contents: dict[str, bytes] = {}
    # Use glob.glob(..., root_dir=...) here once Python 3.9 becomes
    # unsupported.
    storeroom_path_str = os.fsdecode(storeroom_path)
    valid_hashdirs = [
        hashdir_name
        for hashdir_name in os.listdir(storeroom_path_str)
        if fnmatch.fnmatch(hashdir_name, '[01][0-9a-f]')
    ]
    for file in valid_hashdirs:
        bucket_contents = list(
            decrypt_bucket_file(file, master_keys, root_dir=storeroom_path)
        )
        bucket_index = json.loads(bucket_contents.pop(0))
        for pos, item in enumerate(bucket_index):
            json_contents[item] = bucket_contents[pos]
            logger.debug(
                'Found bucket item: %s -> %s', item, bucket_contents[pos]
            )
    dirs_to_check: dict[str, list[str]] = {}
    json_payload: Any
    for path, json_content in sorted(json_contents.items()):
        if path.endswith('/'):
            logger.debug(
                'Postponing dir check: %s -> %s',
                path,
                json_content.decode('utf-8'),
            )
            json_payload = json.loads(json_content)
            if not isinstance(json_payload, list) or any(
                not isinstance(x, str) for x in json_payload
            ):
                msg = (
                    f'Directory index is not actually an index: '
                    f'{json_content!r}'
                )
                raise RuntimeError(msg)
            dirs_to_check[path] = json_payload
            logger.debug(
                'Setting contents (empty directory): %s -> %s', path, '{}'
            )
            _store(config_structure, path, b'{}')
        else:
            logger.debug(
                'Setting contents: %s -> %s',
                path,
                json_content.decode('utf-8'),
            )
            _store(config_structure, path, json_content)
    # Sorted order is important; see `mabye_obj` below.
    for _dir, namelist in sorted(dirs_to_check.items()):
        namelist = [x.rstrip('/') for x in namelist]  # noqa: PLW2901
        obj: dict[Any, Any] = config_structure
        for part in _dir.split('/'):
            if part:
                # Because we iterate paths in sorted order, parent
                # directories are encountered before child directories.
                # So parent directories always exist (lest we would have
                # aborted earlier).
                #
                # Of course, the type checker doesn't necessarily know
                # this, so we need to use assertions anyway.
                maybe_obj = obj.get(part)
                assert isinstance(
                    maybe_obj, dict
                ), f'Cannot traverse storage path {_dir!r}'
                obj = maybe_obj
        if set(obj.keys()) != set(namelist):
            msg = f'Object key mismatch for path {_dir!r}'
            raise RuntimeError(msg)
    return config_structure


if __name__ == '__main__':
    logging.basicConfig(level=('DEBUG' if os.getenv('DEBUG') else 'WARNING'))
    config_structure = export_storeroom_data()
    print(json.dumps(config_structure, indent=2, sort_keys=True))  # noqa: T201
