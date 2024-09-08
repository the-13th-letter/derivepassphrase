# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT
"""Run [`derivepassphrase.cli.derivepassphrase`][] on import."""

import sys

if __name__ == '__main__':
    from derivepassphrase.cli import derivepassphrase

    sys.exit(derivepassphrase())
