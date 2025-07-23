# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Foreign configuration exporter for derivepassphrase."""

from __future__ import annotations

import importlib
import os
import pathlib
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from typing_extensions import Buffer

__all__ = ()


INVALID_VAULT_NATIVE_CONFIGURATION_FORMAT = (
    'Invalid vault native configuration format: {fmt!r}'
)


class NotAVaultConfigError(ValueError):
    """The `path` does not hold a `format`-type vault configuration."""

    def __init__(
        self,
        path: str | bytes | os.PathLike,
        format: str | None = None,  # noqa: A002
    ) -> None:
        self.path = os.fspath(path)
        self.format = format

    def __str__(self) -> str:  # pragma: no cover
        formatted_format = (
            f'vault {self.format} configuration'
            if self.format
            else 'vault configuration'
        )
        return f'Not a {formatted_format}: {self.path!r}'


def get_vault_key() -> bytes:
    """Automatically determine the vault(1) master key/password.

    Query the `VAULT_KEY`, `LOGNAME`, `USER` and `USERNAME` environment
    variables, in that order.  This is the same algorithm that vault
    uses.

    Returns:
        The master key/password.  This is generally used as input to
        a key-derivation function to determine the *actual* encryption
        and signing keys for the vault configuration.

    Raises:
        KeyError:
            We cannot find any of the named environment variables.
            Please set `VAULT_KEY` manually to the desired value.

    """

    def getenv_environb(env_var: str) -> bytes:  # pragma: no cover
        return os.environb.get(env_var.encode('UTF-8'), b'')  # type: ignore[attr-defined]

    def getenv_environ(env_var: str) -> bytes:  # pragma: no cover
        return os.environ.get(env_var, '').encode('UTF-8')

    getenv: Callable[[str], bytes] = (
        getenv_environb if os.supports_bytes_environ else getenv_environ
    )
    username = (
        getenv('VAULT_KEY')
        or getenv('LOGNAME')
        or getenv('USER')
        or getenv('USERNAME')
    )
    if not username:
        env_var = 'VAULT_KEY'
        raise KeyError(env_var)
    return username


def get_vault_path() -> pathlib.Path:
    """Automatically determine the vault(1) configuration path.

    Query the `VAULT_PATH` environment variable, or default to
    `~/.vault`.  This is the same algorithm that vault uses.  If not
    absolute, then `VAULT_PATH` is relative to the home directory.

    Returns:
        The vault configuration path.  Depending on the vault version,
        this may be a file or a directory.

    Raises:
        RuntimeError:
            We cannot determine the home directory.  Please set `HOME`
            manually to the correct value.

    """
    return pathlib.Path(
        '~', os.environ.get('VAULT_PATH', '.vault')
    ).expanduser()


class ExportVaultConfigDataFunction(Protocol):  # pragma: no cover
    """Typing protocol for vault config data export handlers."""

    def __call__(
        self,
        path: str | bytes | os.PathLike | None = None,
        key: str | Buffer | None = None,
        *,
        format: str,  # noqa: A002
    ) -> Any:  # noqa: ANN401
        """Export the full vault-native configuration stored in `path`.

        Args:
            path:
                The path to the vault configuration file or directory.
                If not given, then query [`get_vault_path`][] for the
                correct value.
            key:
                Encryption key/password for the configuration file or
                directory, usually the username, or passed via the
                `VAULT_KEY` environment variable.  If not given, then
                query [`get_vault_key`][] for the value.
            format:
                The format to attempt parsing as.  Must be `v0.2`,
                `v0.3` or `storeroom`.

        Returns:
            The vault configuration, as recorded in the configuration
            file.

            This may or may not be a valid configuration according to
            `vault` or `derivepassphrase`.

        Raises:
            IsADirectoryError:
                The requested format requires a configuration file, but
                `path` points to a directory instead.
            NotADirectoryError:
                The requested format requires a configuration directory,
                but `path` points to something else instead.
            OSError:
                There was an OS error while accessing the configuration
                file/directory.
            RuntimeError:
                Something went wrong during data collection, e.g. we
                encountered unsupported or corrupted data in the
                configuration file/directory.
            json.JSONDecodeError:
                An internal JSON data structure failed to parse from
                disk.  The configuration file/directory is probably
                corrupted.
            exporter.NotAVaultConfigError:
                The file/directory contents are not in the claimed
                configuration format.
            ValueError:
                The requested format is invalid.
            ModuleNotFoundError:
                The requested format requires support code, which failed
                to load because of missing Python libraries.

        """


_export_vault_config_data_registry: dict[
    str,
    ExportVaultConfigDataFunction,
] = {}


def register_export_vault_config_data_handler(
    *names: str,
) -> Callable[[ExportVaultConfigDataFunction], ExportVaultConfigDataFunction]:
    if not names:
        msg = 'No names given to export_data handler registry'
        raise ValueError(msg)
    if '' in names:
        msg = 'Cannot register export_data handler under an empty name'
        raise ValueError(msg)

    def wrapper(
        f: ExportVaultConfigDataFunction,
    ) -> ExportVaultConfigDataFunction:
        for name in names:
            if name in _export_vault_config_data_registry:
                msg = f'export_data handler already registered: {name!r}'
                raise ValueError(msg)
            _export_vault_config_data_registry[name] = f
        return f

    return wrapper


def find_vault_config_data_handlers() -> None:
    """Find all export handlers for vault config data.

    (This function is idempotent.)

    Raises:
        ModuleNotFoundError:
            A required module was not found.

    """
    # Defer imports (and handler registrations) to avoid circular
    # imports.  The modules themselves contain function definitions that
    # register themselves automatically with
    # `_export_vault_config_data_registry`.
    importlib.import_module('derivepassphrase.exporter.storeroom')
    importlib.import_module('derivepassphrase.exporter.vault_native')


def export_vault_config_data(
    path: str | bytes | os.PathLike | None = None,
    key: str | Buffer | None = None,
    *,
    format: str,  # noqa: A002
) -> Any:  # noqa: ANN401
    """Export the full vault-native configuration stored in `path`.

    See [`ExportVaultConfigDataFunction`][] for an explanation of the
    call signature, and the exceptions to expect.

    """  # noqa: DOC201,DOC501
    find_vault_config_data_handlers()
    handler = _export_vault_config_data_registry.get(format)
    if handler is None:
        msg = INVALID_VAULT_NATIVE_CONFIGURATION_FORMAT.format(fmt=format)
        raise ValueError(msg)
    return handler(path, key, format=format)
