# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Unlicense

"""The `always_fail` example SSH agent provider.

The provider always fails to construct a socket.

"""

from __future__ import annotations

import derivepassphrase_sshagentsocketprovider as d_sasp


# Very simple, but uninteresting example.
def always_fail_socket_provider() -> d_sasp.SSHAgentSocket:
    """A provider that always fails to provide an SSH agent socket."""
    msg = "Deliberately failing to construct an SSH agent socket."
    raise RuntimeError(msg)


assert isinstance(always_fail_socket_provider, d_sasp.SSHAgentSocketProvider)
ENTRY_POINT = d_sasp.SSHAgentSocketProviderEntry(
    provider=always_fail_socket_provider, key="always_fail", aliases=("fail",)
)
