# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib
#
# Minimal stub file for the part of the tomli package we actually use.
# Included here so that mypy will find the stubs regardless of whether
# the correct hatch environment is used.

from collections.abc import Callable
from typing import IO, Any

def load(
    __fp: IO[bytes], /, *, parse_float: Callable[..., Any] = ...
) -> dict[str, Any]: ...
