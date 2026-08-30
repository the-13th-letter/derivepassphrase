# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Unlicense

"""The `stdin_stdout` example SSH agent provider.

The provider exposes a virtual socket such that reading from the virtual
socket reads from `sys.stdin`, and writing to the virtual socket writes
to `sys.stdout`.

"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import derivepassphrase_sshagentsocketprovider as d_sasp

if TYPE_CHECKING:
    from typing_extensions import Buffer, Self


# Simple example, forwarding access to certain file-like objects.
class SSHAgentOverStdinStdoutSocket:
    """Forwarding STDIN/STDOUT, as if connected to an SSH agent."""

    FLAGS_ARE_UNSUPPORTED = "flags argument is unsupported"
    """Common error message."""

    def __enter__(self) -> Self:
        """Return self."""
        return self

    def __exit__(self, *args: object) -> bool | None:
        """Close stdin/stdout."""
        sys.stdin.close()
        sys.stdout.close()
        return None

    def send(self, data: Buffer, flags: int = 0, /) -> None:
        """Send data to agent."""
        if flags:
            raise ValueError(self.FLAGS_ARE_UNSUPPORTED)
        sys.stdout.buffer.write(data)

    def recv(self, bufsize: int, flags: int = 0, /) -> bytes:
        """Receive data from agent."""
        if flags:
            raise ValueError(self.FLAGS_ARE_UNSUPPORTED)
        return sys.stdin.buffer.read(bufsize)


SSH_AGENT_OVER_STDIN_STDOUT_PROVIDER = SSHAgentOverStdinStdoutSocket
assert isinstance(
    SSH_AGENT_OVER_STDIN_STDOUT_PROVIDER, d_sasp.SSHAgentSocketProvider
)
ENTRY_POINT = d_sasp.SSHAgentSocketProviderEntry(
    provider=SSH_AGENT_OVER_STDIN_STDOUT_PROVIDER,
    key="stdin_stdout",
    aliases=("stdin", "stdout"),
)
