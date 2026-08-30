# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Unlicense

"""The `failure_response` example SSH agent provider.

The provider creates a pseudo socket which answers every request with an
`SSH_AGENT_FAILURE` response.

"""

from __future__ import annotations

import errno
import os
import struct
import sys
from typing import TYPE_CHECKING, cast

import derivepassphrase_sshagentsocketprovider as d_sasp

if TYPE_CHECKING:
    from typing_extensions import Buffer, Self


# Slightly less simple example, mocking the entire SSH agent.
class FailureSSHAgentSocket:
    """A pseudo socket that always returns failure responses."""

    FLAGS_ARE_UNSUPPORTED = "flags argument is unsupported"
    """Common error message."""
    FAILURE_RESPONSE = b"\x00\x00\x00\x01\x05"
    """Common protocol response: SSH_AGENT_FAILURE."""

    def __init__(self) -> None:
        """Init self."""
        self.closed = False
        """Track whether the channel is already closed."""
        self.send_queue = bytearray()
        """The queue of bytes from the client, filled by [`send`][]."""
        self.recv_queue = bytearray()
        """The queue of bytes to the client, filled by [`recv`][]."""
        self.header_len_struct = struct.Struct(">I")
        """
        A struct used in the parsing of requests.
        Cached for efficiency reasons.
        """

    def __enter__(self) -> Self:
        """Return self."""
        return self

    def __exit__(self, *args: object) -> bool | None:
        """Close the pseudo socket."""
        self.closed = True
        return None

    def send(self, data: Buffer, flags: int = 0, /) -> None:
        """Send data to agent."""
        if self.closed:
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))
        if flags:
            raise ValueError(self.FLAGS_ARE_UNSUPPORTED)
        data_view = memoryview(data)
        self.send_queue.extend(data_view)
        while self._read_one_request():
            self.recv_queue.extend(self.FAILURE_RESPONSE)

    def _read_one_request(self) -> bool:
        """Gobble a complete request from the send_queue, if possible.

        Returns:
            True if a complete request could be gobbled, else False.

        """
        # Protocol requests are framed as [n: = UINT32, PAYLOAD[n]],
        # i.e. a length indicator (as uint32), then a bytes payload of
        # that length.  A request is thus incomplete if and only if it
        # is shorter than 4 bytes (so the UINT32 doesn't fit) or the
        # payload is shorter than the declared length.
        header_size = self.header_len_struct.size
        if len(self.send_queue) < header_size:
            return False
        destructured = cast(
            "tuple[int]", self.header_len_struct.unpack_from(self.send_queue)
        )
        payload_size = destructured[0]
        if len(self.send_queue) < header_size + payload_size:
            return False

        # The queue contains at least header_size + payload_size bytes,
        # so it contains a full request that can be trimmed/gobbled.
        del self.send_queue[: header_size + payload_size]
        return True

    def recv(self, bufsize: int, flags: int = 0, /) -> bytes:
        """Receive data from agent."""
        if self.closed:
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))
        if flags:
            raise ValueError(self.FLAGS_ARE_UNSUPPORTED)
        return self.take_bytes(self.recv_queue, bufsize)

    @staticmethod
    def take_bytes(array: bytearray, n: int | None = None, /) -> bytes:
        """Implementation of `bytearray.take_bytes(n)` from Python 3.15.

        Provided for compatibility with older Pythons.

        Args:
            array:
                The bytearray to take bytes from.
            n:
                The count of bytes to take from the bytearray.  If
                out-of-bounds (when read as an array index), raise
                `IndexError`.  Otherwise, if positive, then take that
                many bytes from the start, or if negative, then leave
                the last `abs(n)` many bytes in the array, and take the
                rest.

        Returns:
            A portion of the original bytearray, as a bytes object.  The
            original bytearray will have that section of bytes removed.

        Raises:
            IndexError:
                The index `n` is invalid.

        Note:
            The compatibility implementation makes no attempt to be a
            zero-copy operation.

        """
        if sys.version_info >= (3, 15):
            return array.take_bytes(n)
        if n is None:
            result = bytes(array)
            array.clear()
            return result
        n2 = n + len(array) if n < 0 else n
        if not (0 <= n2 < len(array)):
            msg = (
                f"Index {n} is out of range for length {len(array)} bytearray"
            )
            raise IndexError(msg)
        result = bytes(array[:n])
        del array[:n]
        return result


FAILURE_SSH_AGENT_PROVIDER = FailureSSHAgentSocket
assert isinstance(FAILURE_SSH_AGENT_PROVIDER, d_sasp.SSHAgentSocketProvider)
ENTRY_POINT = d_sasp.SSHAgentSocketProviderEntry(
    provider=FAILURE_SSH_AGENT_PROVIDER,
    key="failure_agent",
    aliases=(),
)
