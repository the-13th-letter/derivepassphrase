# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Machinery for providing sockets connected to SSH agents."""

from __future__ import annotations

import collections
import ctypes
import enum
import errno
import hashlib
import os
import socket
from ctypes.wintypes import (  # type: ignore[attr-defined]
    BOOL,
    DWORD,
    HANDLE,
    LPCVOID,
    LPCWSTR,
    LPDWORD,
    LPVOID,
)
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import ClassVar

    from typing_extensions import (
        Any,
        Buffer,
        Literal,
        Protocol,
        Self,
        TypeAlias,
        TypeVar,
    )

    from derivepassphrase import _types

    SSHAgentSocketProviderT = TypeVar(
        "SSHAgentSocketProviderT", bound=_types.SSHAgentSocketProvider
    )
    """A parametrized SSH agent socket provider."""

    kernel32: ctypes.WinDLL  # type: ignore[name-defined]
    crypt32: ctypes.WinDLL  # type: ignore[name-defined]

    CryptProtectMemory: Callable[[LPVOID, DWORD, DWORD], BOOL]
    CreateFile: Callable[
        [
            LPCWSTR,
            DWORD,
            DWORD,
            None,
            DWORD,
            DWORD,
            HANDLE | None,
        ],
        HANDLE,
    ]
    ReadFile: Callable[[HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED], BOOL]
    WriteFile: Callable[[HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED], BOOL]
    CloseHandle: Callable[[HANDLE], BOOL]
    GetOverlappedResult: Callable[[HANDLE, LPOVERLAPPED, LPDWORD, BOOL], BOOL]
    CreateEvent: Callable[[None, BOOL, BOOL, None], HANDLE]

    class WinErrorProtocol(Protocol):
        def __call__(self, err: int | None = None, /) -> OSError: ...

    GetLastError: Callable[[], int]
    WinError: WinErrorProtocol


class _OverlappedDummyStruct(ctypes.Structure):
    """The DUMMYSTRUCTNAME structure in the definition of OVERLAPPED."""

    _fields_ = (("Offset", DWORD), ("OffsetHigh", DWORD))


class _OverlappedDummyUnion(ctypes.Union):
    """The DUMMYUNIONNAME union in the definition of OVERLAPPED."""

    _fields_ = (
        ("DUMMYSTRUCTNAME", _OverlappedDummyStruct),
        ("Pointer", ctypes.c_void_p),
    )


class OVERLAPPED(ctypes.Structure):
    """The data structure for overlapped (async) I/O on The Annoying OS."""

    _fields_ = (
        ("Internal", ctypes.POINTER(ctypes.c_ulong)),
        ("InternalHigh", ctypes.POINTER(ctypes.c_ulong)),
        ("DUMMYUNIONNAME", _OverlappedDummyUnion),
        ("hEvent", HANDLE),
    )


if TYPE_CHECKING:
    LPOVERLAPPED: TypeAlias = ctypes._Pointer[OVERLAPPED]  # noqa: SLF001
else:
    LPOVERLAPPED = ctypes.POINTER(OVERLAPPED)

__all__ = ("SocketProvider",)


class NoSuchProviderError(KeyError):
    """No such SSH agent socket provider is known."""


class UnixDomainSocketsNotAvailableError(NotImplementedError):
    """This Python installation does not support UNIX domain sockets.

    On this installation, the standard library symbol
    [`socket.AF_UNIX`][] is not available, necessary to create UNIX
    domain sockets.

    """


class WindowsNamedPipesNotAvailableError(NotImplementedError):
    """This Python installation does not support Windows named pipes.

    On this installation, the standard library symbol
    [`ctypes.WinDLL`][] is not available, necessary to interface with
    the Annoying Operating System's standard library to create Windows
    named pipes.

    """


GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_FLAG_OVERLAPPED = 0x40000000

OPEN_EXISTING = 0x3

INVALID_HANDLE_VALUE = -1

CRYPTPROTECTMEMORY_BLOCK_SIZE = 0x10
CRYPTPROTECTMEMORY_CROSS_PROCESS = 0x1

PIPE_PREFIX = "//./pipe/".replace("/", "\\")

ERROR_PIPE_BUSY = 231
ERROR_IO_PENDING = 997


# The type checker and the standard library use different
# (finer-grained?) types and type definitions on The Annoying Operating
# System to annotate things derived from ctypes.WinDLL.  Furthermore, on
# other OSes, ctypes.WinDLL is missing entirely.  So the type checker
# attempts to validate our code against *very* different type
# hierarchies, depending on what OS it is running on, and so we require
# a lot of type checking exclusions to keep the types reasonably narrow.
#
# Additionally, the official documentation for kernel32.dll and
# crypt32.dll (and The Annoying OS in general) uses CamelCase for both
# function names and function parameters.  This clashes with the
# standard Python naming conventions, so we need linting exclusions for
# each such name.
#
# Finally, since this code is mostly platform-specific, we use coverage
# pragmas for the respective branches to avoid surprises about missing
# coverage.
#
# All these factors necessitate *a lot* of "type: ignore", "noqa:" and
# "pragma: ... no cover" comments below.

try:  # pragma: unless the-annoying-os no cover
    import ctypes

    GetLastError = ctypes.GetLastError  # type: ignore[attr-defined]
    WinError = ctypes.WinError  # type: ignore[attr-defined]
except (
    AttributeError,
    FileNotFoundError,
    ImportError,
):  # pragma: unless posix no cover

    def GetLastError() -> int:  # noqa: N802  # pragma: no cover [failsafe]
        raise NotImplementedError

    def WinError(err: int | None = None, /) -> OSError:  # noqa: N802  # pragma: no cover [failsafe]
        raise NotImplementedError


try:  # pragma: unless the-annoying-os no cover
    crypt32 = ctypes.WinDLL("crypt32.dll")  # type: ignore[attr-defined]
    CryptProtectMemory = crypt32.CryptProtectMemory  # type: ignore[attr-defined]
except (
    AttributeError,
    FileNotFoundError,
    ImportError,
):  # pragma: unless posix no cover

    def CryptProtectMemory(  # noqa: N802
        pDataIn: LPVOID,  # noqa: N803
        cbDataIn: DWORD,  # noqa: N803
        dwFlags: DWORD,  # noqa: N803
    ) -> BOOL:  # pragma: no cover [external]
        del pDataIn, cbDataIn, dwFlags
        raise NotImplementedError

else:  # pragma: unless the-annoying-os no cover
    CryptProtectMemory.argtypes = [LPVOID, DWORD, DWORD]  # type: ignore[attr-defined]
    CryptProtectMemory.restype = BOOL  # type: ignore[attr-defined]


def _errcheck(
    result: int,
    func: Callable,
    arguments: Any,  # noqa: ANN401
) -> int:  # pragma: no cover [external]
    del func
    del arguments
    # Even if they have the same value, ctypes pointers don't
    # compare equal to each other.  We need to compare the values
    # explicitly, keeping the ranges in mind as well.
    result_value = HANDLE(result).value
    invalid_value = HANDLE(INVALID_HANDLE_VALUE).value
    if result_value == invalid_value:
        raise WinError()
    assert result_value is not None  # for the type checker
    return result_value


try:  # pragma: unless the-annoying-os no cover
    kernel32 = ctypes.WinDLL("Kernel32.dll")  # type: ignore[attr-defined]
    CreateFile = kernel32.CreateFileW  # type: ignore[attr-defined]
    ReadFile = kernel32.ReadFile  # type: ignore[attr-defined]
    WriteFile = kernel32.WriteFile  # type: ignore[attr-defined]
    CloseHandle = kernel32.CloseHandle  # type: ignore[attr-defined]
    GetOverlappedResult = kernel32.GetOverlappedResult  # type: ignore[attr-defined]
    CreateEvent = kernel32.CreateEventW  # type: ignore[attr-defined]
except (
    AttributeError,
    FileNotFoundError,
):  # pragma: unless posix no cover

    def CreateFile(  # noqa: N802, PLR0913, PLR0917
        lpFilename: LPCWSTR,  # noqa: N803
        dwDesiredAccess: DWORD,  # noqa: N803
        dwShareMode: DWORD,  # noqa: N803
        lpSecurityAttributes: None,  # noqa: N803
        dwCreationDisposition: DWORD,  # noqa: N803
        dwFlagsAndAttributes: DWORD,  # noqa: N803
        hTemplateFile: HANDLE | None,  # noqa: N803
    ) -> HANDLE:  # pragma: no cover [external]
        del (
            lpFilename,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile,
        )
        msg = "This Python version does not support Windows named pipes."
        raise WindowsNamedPipesNotAvailableError(msg)

    def ReadFile(  # noqa: N802
        hFile: HANDLE,  # noqa: N803
        lpBuffer: LPVOID,  # noqa: N803
        nNumberOfBytesToRead: DWORD,  # noqa: N803
        lpNumberOfBytesRead: LPDWORD,  # noqa: N803
        lpOverlapped: LPOVERLAPPED,  # noqa: N803
    ) -> BOOL:  # pragma: no cover [external]
        del (
            hFile,
            lpBuffer,
            nNumberOfBytesToRead,
            lpNumberOfBytesRead,
            lpOverlapped,
        )
        raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))

    def WriteFile(  # noqa: N802
        hFile: HANDLE,  # noqa: N803
        lpBuffer: LPVOID,  # noqa: N803
        nNumberOfBytesToWrite: DWORD,  # noqa: N803
        lpNumberOfBytesWritten: LPDWORD,  # noqa: N803
        lpOverlapped: LPOVERLAPPED,  # noqa: N803
    ) -> BOOL:  # pragma: no cover [external]
        del (
            hFile,
            lpBuffer,
            nNumberOfBytesToWrite,
            lpNumberOfBytesWritten,
            lpOverlapped,
        )
        raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))

    def CloseHandle(  # noqa: N802
        hHandle: HANDLE,  # noqa: N803
    ) -> BOOL:  # pragma: no cover [external]
        del hHandle
        raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))

    def GetOverlappedResult(  # noqa: N802
        hFile: HANDLE,  # noqa: N803
        lpOverlapped: LPOVERLAPPED,  # noqa: N803
        lpNumberOfBytesTransferred: LPDWORD,  # noqa: N803
        bWait: BOOL,  # noqa: N803
    ) -> BOOL:  # pragma: no cover [external]
        del hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait
        raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))

    def CreateEvent(  # noqa: N802
        lpEventAttributes: None,  # noqa: N803
        bManualReset: BOOL,  # noqa: N803
        bInitialState: BOOL,  # noqa: N803
        lpName: None,  # noqa: N803
    ) -> HANDLE:  # pragma: no cover [external]
        del lpEventAttributes, bManualReset, bInitialState, lpName
        raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))


else:  # pragma: unless the-annoying-os no cover
    CreateFile.argtypes = [  # type: ignore[attr-defined]
        LPCWSTR,
        DWORD,
        DWORD,
        # Actually, LPSECURITY_ATTRIBUTES, but we always pass
        # None/NULL.
        ctypes.c_void_p,
        DWORD,
        DWORD,
        # We always pass None/NULL.
        HANDLE,
    ]
    CreateEvent.argtypes = [  # type: ignore[attr-defined]
        # Actually, LPSECURITY_ATTRIBUTES, but we always pass
        # None/NULL.
        ctypes.c_void_p,
        BOOL,
        BOOL,
        # We always pass None/NULL.
        LPCWSTR,
    ]
    CreateFile.restype = HANDLE  # type: ignore[attr-defined]
    CreateEvent.restype = HANDLE  # type: ignore[attr-defined]
    CreateFile.errcheck = _errcheck  # type: ignore[assignment, attr-defined]
    CreateEvent.errcheck = _errcheck  # type: ignore[assignment, attr-defined]
    ReadFile.argtypes = [  # type: ignore[attr-defined]
        HANDLE,
        LPVOID,
        DWORD,
        LPDWORD,
        LPOVERLAPPED,
    ]
    WriteFile.argtypes = [  # type: ignore[attr-defined]
        HANDLE,
        LPVOID,
        DWORD,
        LPDWORD,
        LPOVERLAPPED,
    ]
    CloseHandle.argtypes = [HANDLE]  # type: ignore[attr-defined]
    GetOverlappedResult.argtypes = [  # type: ignore[attr-defined]
        HANDLE,
        LPOVERLAPPED,
        LPDWORD,
        # We always pass True.
        BOOL,
    ]
    ReadFile.restype = BOOL  # type: ignore[attr-defined]
    WriteFile.restype = BOOL  # type: ignore[attr-defined]
    CloseHandle.restype = BOOL  # type: ignore[attr-defined]
    GetOverlappedResult.restype = BOOL  # type: ignore[attr-defined]


class WindowsNamedPipeHandle:
    """A Windows named pipe handle.

    This handle implements the [`SSHAgentSocket`][_types.SSHAgentSocket]
    interface.  It is only constructable if the Python installation can
    successfully call into the Annoying OS `kernel32.dll` library via
    [`ctypes`][].

    """

    _IO_ON_CLOSED_FILE = "I/O operation on closed file."

    def __init__(
        self, name: str
    ) -> None:  # pragma: unless the-annoying-os no cover
        """Create a named pipe handle.

        Args:
            name:
                The named pipe's name.

        Raises:
            OSError:
                The system failed to open the named pipe.
            ValueError:
                The named pipe's name does not designate a named pipe.
            WindowsNamedPipesNotAvailableError:
                This Python version does not support Windows named
                pipes.

        """
        if not name.replace("/", "\\").startswith(PIPE_PREFIX):
            raise ValueError(errno.EINVAL, os.strerror(errno.EINVAL))
        self.handle: HANDLE | None = None
        while self.handle is None:
            try:
                self.handle = CreateFile(
                    ctypes.c_wchar_p(name),
                    ctypes.c_ulong(GENERIC_READ | GENERIC_WRITE),
                    ctypes.c_ulong(FILE_SHARE_READ | FILE_SHARE_WRITE),
                    None,
                    ctypes.c_ulong(OPEN_EXISTING),
                    ctypes.c_ulong(FILE_FLAG_OVERLAPPED),
                    None,
                )
            except BlockingIOError:  # pragma: no cover [external]
                continue  # retry
            except OSError as exc:  # pragma: no cover [external]
                if getattr(exc, "winerror", None) == ERROR_PIPE_BUSY:
                    continue  # retry
                raise

    def __enter__(self) -> Self:  # pragma: unless the-annoying-os no cover
        return self

    def __exit__(
        self, *args: object
    ) -> Literal[False]:  # pragma: unless the-annoying-os no cover
        try:
            if self.handle is not None:
                CloseHandle(self.handle)
            return False
        finally:
            self.handle = None

    def recv(
        self, data: int, flags: int = 0, /
    ) -> bytes:  # pragma: unless the-annoying-os no cover
        if self.handle is None:
            raise ValueError(self._IO_ON_CLOSED_FILE)
        del flags
        result = bytearray()
        read_count = DWORD(0)
        buffer = (ctypes.c_char * 65536)()
        while data > 0:
            block_size = min(max(0, data), 65536)
            wait_event = CreateEvent(None, BOOL(True), BOOL(False), None)  # noqa: FBT003
            try:
                overlapped_struct = OVERLAPPED(hEvent=wait_event)
                success = ReadFile(
                    self.handle,
                    ctypes.cast(ctypes.byref(buffer), ctypes.c_void_p),
                    DWORD(block_size),
                    ctypes.cast(ctypes.byref(read_count), LPDWORD),
                    ctypes.cast(ctypes.byref(overlapped_struct), LPOVERLAPPED),
                )
                if not success and GetLastError() == ERROR_IO_PENDING:
                    success = GetOverlappedResult(
                        self.handle,
                        ctypes.cast(
                            ctypes.byref(overlapped_struct), LPOVERLAPPED
                        ),
                        ctypes.cast(ctypes.byref(read_count), LPDWORD),
                        BOOL(True),  # noqa: FBT003
                    )
                if (
                    not success or read_count.value == 0
                ):  # pragma: no cover [external]
                    raise WinError()
            finally:
                CloseHandle(wait_event)
            result.extend(buffer.raw[:block_size])
            data -= read_count.value
            read_count.value = 0
        return bytes(result)

    def sendall(
        self, data: Buffer, flags: int = 0, /
    ) -> None:  # pragma: unless the-annoying-os no cover
        if self.handle is None:
            raise ValueError(self._IO_ON_CLOSED_FILE)
        del flags
        data = bytes(data)
        databuf = (ctypes.c_char * len(data))()
        for i, x in enumerate(data):
            databuf[i] = ctypes.c_char(x)
        write_count = DWORD(0)
        wait_event = CreateEvent(None, BOOL(True), BOOL(False), None)  # noqa: FBT003
        try:
            overlapped_struct = OVERLAPPED(hEvent=wait_event)
            success = WriteFile(
                self.handle,
                ctypes.cast(ctypes.byref(databuf), ctypes.c_void_p),
                DWORD(len(data)),
                ctypes.cast(ctypes.byref(write_count), LPDWORD),
                ctypes.cast(ctypes.byref(overlapped_struct), LPOVERLAPPED),
            )
            if not success and GetLastError() == ERROR_IO_PENDING:
                success = GetOverlappedResult(
                    self.handle,
                    ctypes.cast(ctypes.byref(overlapped_struct), LPOVERLAPPED),
                    ctypes.cast(ctypes.byref(write_count), LPDWORD),
                    BOOL(True),  # noqa: FBT003
                )
            if (
                not success or write_count.value == 0
            ):  # pragma: no cover [external]
                raise WinError()
        finally:
            CloseHandle(wait_event)

    @classmethod
    def for_openssh(cls) -> Self:  # pragma: unless the-annoying-os no cover
        """Construct a named pipe for use with OpenSSH on The Annoying OS.

        Returns:
            A new named pipe handle, using OpenSSH's pipe name.

        """
        return cls(f"{PIPE_PREFIX}openssh-ssh-agent")

    @classmethod
    def for_pageant(cls) -> Self:  # pragma: unless the-annoying-os no cover
        """Construct a named pipe for use with Pageant.

        Returns:
            A new named pipe handle, using Pageant's pipe name.

        """
        return cls(cls.pageant_named_pipe_name())

    @staticmethod
    def pageant_named_pipe_name(
        *,
        require_cryptprotectmemory: bool = False,
    ) -> str:  # pragma: unless the-annoying-os no cover
        """Return the pipe name that Pageant on The Annoying OS would use.

        Args:
            require_cryptprotectmemory:
                Pageant normally attempts to use the
                `CryptProtectMemory` system function from the
                `crypt32.dll` library on The Annoying OS, ignoring any
                errors.  This in turn influences the resulting named
                pipe's filename.

                If true, and if we fail to call `CryptProtectMemory`, we
                abort; otherwise we ignore any errors from calling or
                failing to call `CryptProtectMemory`.

        Raises:
            NotImplementedError:
                `require_cryptprotectmemory` was `True`, but this Python
                version cannot call `CryptProtectMemory` due to lack of
                system support.

        """
        realname = b"Pageant\x00"
        num_blocks = (
            len(realname) + CRYPTPROTECTMEMORY_BLOCK_SIZE - 1
        ) // CRYPTPROTECTMEMORY_BLOCK_SIZE
        assert num_blocks == 1
        buf_decl = ctypes.c_char * (CRYPTPROTECTMEMORY_BLOCK_SIZE * num_blocks)
        buf = buf_decl()
        for i, x in enumerate(realname):
            buf[i] = ctypes.c_char(x)
        try:
            CryptProtectMemory(
                ctypes.cast(ctypes.byref(buf), ctypes.c_void_p),
                DWORD(len(buf.raw)),
                DWORD(CRYPTPROTECTMEMORY_CROSS_PROCESS),
            )
        except NotImplementedError:  # pragma: no cover [external]
            if require_cryptprotectmemory:
                raise
        buf_as_ssh_string = bytearray()
        buf_as_ssh_string.extend(int.to_bytes(len(buf.raw), 4, "big"))
        buf_as_ssh_string.extend(buf.raw)
        digest = hashlib.sha256(buf_as_ssh_string).hexdigest()
        return f"{PIPE_PREFIX}pageant.{os.getlogin()}.{digest}"


class _WindowsNamedPipeSocketAddress(enum.Enum):
    """Internal enum for the socket address for Windows named pipes.

    Attributes:
        PAGEANT: The dynamic address for PuTTY/Pageant.
        OPENSSH: The static address for OpenSSH-on-Windows.

    """

    PAGEANT = "PuTTY/Pageant on The Annoying OS"
    """"""
    OPENSSH = "OpenSSH on The Annoying OS"
    """"""


class SocketProvider:
    """Static functionality for providing sockets."""

    @staticmethod
    def unix_domain_ssh_auth_sock(*, timeout: int = 125) -> socket.socket:
        """Return a UNIX domain socket connected to `SSH_AUTH_SOCK`.

        Args:
            timeout:
                A connection timeout for the SSH agent.  Only used for
                "true" sockets, and only if the socket is not yet connected.
                The default value gives ample time for agent connections
                forwarded via SSH on high-latency networks (e.g. Tor).

        Returns:
            A connected UNIX domain socket.

        Raises:
            KeyError:
                The `SSH_AUTH_SOCK` environment variable was not found.
            UnixDomainSocketsNotAvailableError:
                This Python version does not support UNIX domain
                sockets, necessary to automatically connect to
                a running SSH agent via the `SSH_AUTH_SOCK` environment
                variable.
            OSError:
                There was an error setting up a socket connection to the
                agent.

        """
        if not hasattr(socket, "AF_UNIX"):
            msg = "This Python version does not support UNIX domain sockets."
            raise UnixDomainSocketsNotAvailableError(msg)
        else:  # noqa: RET506  # pragma: unless posix no cover
            sock = socket.socket(family=socket.AF_UNIX)
            if "SSH_AUTH_SOCK" not in os.environ:
                msg = "SSH_AUTH_SOCK environment variable"
                raise KeyError(msg)
            ssh_auth_sock = os.environ["SSH_AUTH_SOCK"]
            sock.settimeout(timeout)
            sock.connect(ssh_auth_sock)
            return sock

    @staticmethod
    def _windows_named_pipe(
        pipe_name: _WindowsNamedPipeSocketAddress | str,
    ) -> _types.SSHAgentSocket:
        """Return a socket wrapper around a Windows named pipe.

        Raises:
            OSError:
                There was an error setting up a connection to the agent.
            WindowsNamedPipesNotAvailableError:
                This Python version does not support Windows named
                pipes.

        """
        if not hasattr(ctypes, "WinDLL"):
            msg = "This Python version does not support Windows named pipes."
            raise WindowsNamedPipesNotAvailableError(msg)
        else:  # noqa: RET506  # pragma: unless the-annoying-os no cover
            # TODO(the-13th-letter): Rewrite using structural pattern
            # matching.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
            if pipe_name == _WindowsNamedPipeSocketAddress.PAGEANT:
                return WindowsNamedPipeHandle.for_pageant()
            if pipe_name == _WindowsNamedPipeSocketAddress.OPENSSH:
                return WindowsNamedPipeHandle.for_openssh()
            return WindowsNamedPipeHandle(pipe_name)

    @classmethod
    def windows_named_pipe_for_pageant(cls) -> _types.SSHAgentSocket:
        """Return a socket wrapper connected to Pageant on The Annoying OS.

        Raises:
            OSError:
                There was an error setting up a connection to Pageant.
            WindowsNamedPipesNotAvailableError:
                This Python version does not support Windows named
                pipes.

        """
        return cls._windows_named_pipe(_WindowsNamedPipeSocketAddress.PAGEANT)

    @classmethod
    def windows_named_pipe_for_openssh(cls) -> _types.SSHAgentSocket:
        """Return a socket wrapper connected to the OpenSSH agent on The Annoying OS.

        Raises:
            OSError:
                There was an error setting up a connection to the OpenSSH
                agent.
            WindowsNamedPipesNotAvailableError:
                This Python version does not support Windows named
                pipes.

        """  # noqa: E501
        return cls._windows_named_pipe(_WindowsNamedPipeSocketAddress.OPENSSH)

    @classmethod
    def windows_named_pipe_ssh_auth_sock(cls) -> _types.SSHAgentSocket:
        r"""Return a socket wrapper connected to the agent in `SSH_AUTH_SOCK`.

        The `SSH_AUTH_SOCK` environment variable is assumed to contain
        a valid named pipe name, i.e., a path starting with `\\.\pipe\`
        or `//./pipe/`.

        Raises:
            KeyError:
                The `SSH_AUTH_SOCK` environment variable was not found.
            ValueError:
                The path in `SSH_AUTH_SOCK` clearly does not name a valid
                named pipe name.
            OSError:
                There was an error setting up a connection to the OpenSSH
                agent.
            WindowsNamedPipesNotAvailableError:
                This Python version does not support Windows named
                pipes.

        """
        address = os.environ["SSH_AUTH_SOCK"]
        if not address.replace("/", "\\").startswith(PIPE_PREFIX):
            msg = f"Invalid named pipe name: {address!r}"
            raise ValueError(msg)
        return cls._windows_named_pipe(address)

    registry: ClassVar[
        dict[str, _types.SSHAgentSocketProvider | str | None]
    ] = {}
    """A dictionary of callables that provide SSH agent sockets.

    Each entry in the dictionary points either to a callable, a string,
    or `None`: if a callable, then that callable returns a socket; if
    a string, then this entry is an alias for that other entry; if
    `None`, then the entry name is merely registered, but no
    implementation is available.

    If a callable is not applicable to this platform, Python
    installation or `derivepassphrase` installation, then it MUST raise
    [`NotImplementedError`][].  Conversely, if the callable returns
    a value, or raises any other kind of exception, then the caller MAY
    assume that this platform, Python installation and
    `derivepassphrase` installation are sufficient for the callable to
    be able to return a working socket on this platform.  (The latter
    may still be dependent on further, external circumstances, such as
    required configuration settings, or environment variables, or
    sufficient system resources, etc.)

    (Interpretation of "MUST" and "MAY" as per IETF Best Current
    Practice #14; see [RFC 2119][] and [RFC 8174][].)

    [RFC 2119]: https://www.rfc-editor.org/info/rfc2119
    [RFC 8174]: https://www.rfc-editor.org/info/rfc8174

    """

    @classmethod
    def register(
        cls,
        name: str,
        *aliases: str,
    ) -> Callable[[SSHAgentSocketProviderT], SSHAgentSocketProviderT]:
        """Register a callable as an SSH agent socket provider (decorator).

        Attempting to re-register an existing alias, or a name with an
        implementation, with a different implementation is an error.

        Args:
            name:
                The principal name under which to register the passed
                callable.
            aliases:
                Alternate names to register as aliases for the principal
                name.

        Returns:
            A decorator implementing the above.

        """

        def decorator(f: SSHAgentSocketProviderT) -> SSHAgentSocketProviderT:
            """Register a callable as an SSH agent socket provider.

            Attempting to re-register an existing alias, or a name with
            an implementation, with a different implementation is an
            error.

            Args:
                f: The callable to decorate/register.

            Returns:
                The callable.

            Raises:
                ValueError:
                    The name or alias is already in use.

            """
            for alias in [name, *aliases]:
                try:
                    existing = cls.lookup(alias)
                except (NoSuchProviderError, NotImplementedError):
                    cls.registry[alias] = f if alias == name else name
                else:
                    if existing is None:
                        cls.registry[alias] = f if alias == name else name
                    elif existing != f:
                        msg = (
                            f"The SSH agent socket provider {alias!r} "
                            f"is already registered."
                        )
                        raise ValueError(msg)
            return f

        return decorator

    @classmethod
    def lookup(
        cls, provider: _types.SSHAgentSocketProvider | str | None, /
    ) -> _types.SSHAgentSocketProvider | None:
        """Look up a socket provider entry.

        Args:
            provider: The provider to look up.

        Returns:
            The callable indicated by this provider, if it is
            implemented, or `None`, if it is merely registered.

        Raises:
            NoSuchProviderError:
                The provider is not registered.

        """
        ret = provider
        while isinstance(ret, str):
            try:
                ret = cls.registry[ret]
            except KeyError as exc:
                raise NoSuchProviderError(ret) from exc
        return ret

    @classmethod
    def resolve(
        cls, provider: _types.SSHAgentSocketProvider | str | None, /
    ) -> _types.SSHAgentSocketProvider:
        """Resolve a socket provider to a proper callable.

        Args:
            provider: The provider to resolve.

        Returns:
            The callable indicated by this provider.

        Raises:
            NoSuchProviderError:
                The provider is not registered.
            NotImplementedError:
                The provider is registered, but is not functional or not
                applicable to this `derivepassphrase` installation.

        """
        ret = cls.lookup(provider)
        if ret is None:
            msg = (
                f"The {ret!r} socket provider is not functional on or "
                "not applicable to this derivepassphrase installation."
            )
            raise NotImplementedError(msg)
        return ret

    ENTRY_POINT_GROUP_NAME = "derivepassphrase.ssh_agent_socket_providers"
    """
    The group name under which [entry
    points][importlib.metadata.entry_points] for the SSH agent socket
    provider registry should be recorded.  Each target of such an entry
    point should be a [`_types.SSHAgentSocketProviderEntry`][] object.
    """

    @classmethod
    def _find_all_ssh_agent_socket_providers(cls) -> None:
        """Find and load all declared SSH agent socket providers.

        Load all [entry points][importlib.metadata.entry_points] in the
        `derivepassphrase.ssh_agent_socket_providers` group as providers,
        then register them.  The target of each entry point should be
        a [`_types.SSHAgentSocketProviderEntry`][] object.

        Raises:
            AssertionError:
                The declared SSH agent socket provider was not, in fact,
                an SSH agent socket provider.

                Alternatively, multiple distributions supplied the same
                SSH agent socket provider, but with different
                implementations.

        """
        import importlib.metadata  # noqa: PLC0415

        origins: dict[str, str | None] = {}
        entries = collections.ChainMap({}, cls.registry)
        for entry_point in importlib.metadata.entry_points(
            group=cls.ENTRY_POINT_GROUP_NAME
        ):
            provider_entry = cast(
                "_types.SSHAgentSocketProviderEntry", entry_point.load()
            )
            key = provider_entry.key
            value = entry_point.value
            dist = (
                entry_point.dist.name  # type: ignore[union-attr]
                if getattr(entry_point, "dist", None) is not None
                else "<unknown>"
            )
            origin = origins.get(key, "derivepassphrase")
            if not callable(provider_entry.provider):
                msg = (
                    f"Not an SSHAgentSocketProvider: "
                    f"{dist = }, {cls.ENTRY_POINT_GROUP_NAME = }, "
                    f"{value = }, {provider_entry = }"
                )
                raise AssertionError(msg)  # noqa: TRY004
            if key in entries:
                if entries[key] != provider_entry.provider:
                    msg = (
                        f"Name clash in SSH agent socket providers "
                        f"for entry {key!r}, both by {dist!r} "
                        f"and by {origin!r}"
                    )
                    raise AssertionError(msg)
            else:
                entries[key] = provider_entry.provider
                origins[key] = dist
            for alias in provider_entry.aliases:
                alias_origin = origins.get(alias, "derivepassphrase")
                if alias in entries:
                    if entries[alias] != key:
                        msg = (
                            f"Name clash in SSH agent socket providers "
                            f"for entry {alias!r}, both by {dist!r} "
                            f"and by {alias_origin!r}"
                        )
                        raise AssertionError(msg)
                else:
                    entries[alias] = key
                    origins[key] = dist
        cls.registry.update(entries.maps[0])


SocketProvider.registry.update({
    "ssh_auth_sock_on_posix": SocketProvider.unix_domain_ssh_auth_sock,
    "pageant_on_the_annoying_os": SocketProvider.windows_named_pipe_for_pageant,  # noqa: E501
    "openssh_on_the_annoying_os": SocketProvider.windows_named_pipe_for_openssh,  # noqa: E501
    "ssh_auth_sock_on_the_annoying_os": SocketProvider.windows_named_pipe_ssh_auth_sock,  # noqa: E501
    # known instances
    "stub_agent": None,
    "stub_agent_with_address": None,
    "stub_agent_with_address_and_deterministic_dsa": None,
    # aliases
    "posix": "ssh_auth_sock_on_posix",
    "ssh_auth_sock": "ssh_auth_sock_on_posix",
    "unix_domain": "ssh_auth_sock_on_posix",
    "the_annoying_os": "ssh_auth_sock_on_the_annoying_os",
    "the_annoying_os_named_pipe": "the_annoying_os",
    "windows": "the_annoying_os",
    "windows_named_pipe": "the_annoying_os",
    "pageant_on_windows": "pageant_on_the_annoying_os",
    "openssh_on_windows": "openssh_on_the_annoying_os",
    "native": "the_annoying_os" if os.name == "nt" else "posix",
})
