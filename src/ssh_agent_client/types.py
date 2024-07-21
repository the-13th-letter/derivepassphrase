# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Common typing declarations for the parent module."""

from __future__ import annotations

import enum
from typing import NamedTuple

__all__ = ('SSH_AGENT', 'SSH_AGENTC', 'KeyCommentPair')


class KeyCommentPair(NamedTuple):
    """SSH key plus comment pair.  For typing purposes.

    Attributes:
        key: SSH key.
        comment: SSH key comment.

    """

    key: bytes | bytearray
    comment: bytes | bytearray


class SSH_AGENTC(enum.Enum):  # noqa: N801
    """SSH agent protocol numbers: client requests.

    Attributes:
        REQUEST_IDENTITIES:
            List identities.  Expecting `SSH_AGENT.IDENTITIES_ANSWER`.
        SIGN_REQUEST:
            Sign data.  Expecting `SSH_AGENT.SIGN_RESPONSE`.

    """

    REQUEST_IDENTITIES: int = 11
    SIGN_REQUEST: int = 13


class SSH_AGENT(enum.Enum):  # noqa: N801
    """SSH agent protocol numbers: server replies.

    Attributes:
        IDENTITIES_ANSWER:
            Successful answer to `SSH_AGENTC.REQUEST_IDENTITIES`.
        SIGN_RESPONSE:
            Successful answer to `SSH_AGENTC.SIGN_REQUEST`.

    """

    IDENTITIES_ANSWER: int = 12
    SIGN_RESPONSE: int = 14
