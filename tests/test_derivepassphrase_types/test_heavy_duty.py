# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import math

import hypothesis
from hypothesis import strategies
from typing_extensions import Any

import tests.machinery.pytest
from derivepassphrase import _types

# All tests in this module are heavy-duty tests.
pytestmark = [tests.machinery.pytest.heavy_duty]


@strategies.composite
def js_atoms_strategy(
    draw: strategies.DrawFn,
) -> int | float | str | bytes | bool | None:
    """Yield a JS atom."""
    return draw(
        strategies.one_of(
            strategies.integers(),
            strategies.floats(allow_nan=False, allow_infinity=False),
            strategies.text(max_size=100),
            strategies.binary(max_size=100),
            strategies.booleans(),
            strategies.none(),
        ),
    )


@strategies.composite
def js_nested_strategy(draw: strategies.DrawFn) -> Any:
    """Yield an arbitrary and perhaps nested JS value."""
    return draw(
        strategies.one_of(
            js_atoms_strategy(),
            strategies.builds(tuple),
            strategies.builds(list),
            strategies.builds(dict),
            strategies.builds(set),
            strategies.builds(frozenset),
            strategies.recursive(
                js_atoms_strategy(),
                lambda s: strategies.one_of(
                    strategies.frozensets(s, max_size=100),
                    strategies.builds(
                        tuple, strategies.frozensets(s, max_size=100)
                    ),
                ),
                max_leaves=8,
            ),
            strategies.recursive(
                js_atoms_strategy(),
                lambda s: strategies.one_of(
                    strategies.lists(s, max_size=100),
                    strategies.dictionaries(strategies.text(max_size=100), s),
                ),
                max_leaves=25,
            ),
        ),
    )


@hypothesis.given(value=js_nested_strategy())
@hypothesis.example(float("nan"))
def test_100_js_truthiness(value: Any) -> None:
    """Determine the truthiness of a value according to JavaScript.

    Use hypothesis to generate test values.

    """
    expected = (
        value is not None  # noqa: PLR1714
        and value != False  # noqa: E712
        and value != 0
        and value != 0.0
        and value != ""
        and not (isinstance(value, float) and math.isnan(value))
    )
    assert _types.js_truthiness(value) == expected
