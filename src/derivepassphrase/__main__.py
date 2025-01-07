# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib
"""Run [`derivepassphrase.cli.derivepassphrase`][] on import."""

import sys

if __name__ == '__main__':
    from derivepassphrase.cli import derivepassphrase

    sys.exit(derivepassphrase())
