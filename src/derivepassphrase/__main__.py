# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT
import sys

if __name__ == "__main__":
    from derivepassphrase.cli import derivepassphrase

    sys.exit(derivepassphrase())
