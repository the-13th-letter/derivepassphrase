# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Unlicense

"""Example SSH agent providers.

We package three examples:

 1. The `stdin_stdout` example is the simplest useful one. The provider
    exposes a virtual socket such that reading from the virtual socket
    reads from `sys.stdin`, and writing to the virtual socket writes to
    `sys.stdout`.
 2. The `failure_response` example is a somewhat more complicated, but
    also more useful one. The provider creates a pseudo socket which
    answers every request with an `SSH_AGENT_FAILURE` response.
 3. The `always_fail` example is very simple, but not very useful.  The
    provider always fails to construct a socket.

See the respective submodule for the code.

"""

__version__ = "0.0.0"
