# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""`hypothesis` testing machinery for the `derivepassphrase` test suite.

This is all the `hypothesis`-specific data and functionality used in the
`derivepassphrase` test suite; this includes custom `hypothesis`
strategies, or state machines, or state machine helper functions, or
functions interacting with the `hypothesis` settings.

All similar-minded code requiring only plain `pytest` lives in [the
`pytest` sibling module][tests.machinery.pytest].

"""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

import hypothesis
from hypothesis import strategies

import tests.data
import tests.machinery
from derivepassphrase import _types

__all__ = ()

if TYPE_CHECKING:
    from typing_extensions import Any


# Hypothesis settings management
# ==============================


def get_concurrency_step_count(
    settings: hypothesis.settings | None = None,
) -> int:
    """Return the desired step count for concurrency-related tests.

    This is the smaller of the [general concurrency
    limit][tests.machinery.get_concurrency_limit] and the step count
    from the current hypothesis settings.

    Args:
        settings:
            The hypothesis settings for a specific tests.  If not given,
            then the current profile will be queried directly.

    """
    if settings is None:  # pragma: no cover
        settings = hypothesis.settings()
    return min(tests.machinery.get_concurrency_limit(), settings.stateful_step_count)


# Hypothesis strategies
# =====================


@strategies.composite
def vault_full_service_config(draw: strategies.DrawFn) -> dict[str, int]:
    """Hypothesis strategy for full vault service configurations.

    Returns a sample configuration with restrictions on length, repeat
    count, and all character classes, while ensuring the settings are
    not obviously unsatisfiable.

    Args:
        draw:
            The `draw` function, as provided for by hypothesis.

    """
    repeat = draw(strategies.integers(min_value=0, max_value=10))
    lower = draw(strategies.integers(min_value=0, max_value=10))
    upper = draw(strategies.integers(min_value=0, max_value=10))
    number = draw(strategies.integers(min_value=0, max_value=10))
    space = draw(strategies.integers(min_value=0, max_value=repeat))
    dash = draw(strategies.integers(min_value=0, max_value=10))
    symbol = draw(strategies.integers(min_value=0, max_value=10))
    length = draw(
        strategies.integers(
            min_value=max(1, lower + upper + number + space + dash + symbol),
            max_value=70,
        )
    )
    hypothesis.assume(lower + upper + number + dash + symbol > 0)
    hypothesis.assume(lower + upper + number + space + symbol > 0)
    hypothesis.assume(repeat >= space)
    return {
        "lower": lower,
        "upper": upper,
        "number": number,
        "space": space,
        "dash": dash,
        "symbol": symbol,
        "repeat": repeat,
        "length": length,
    }


@strategies.composite
def smudged_vault_test_config(
    draw: strategies.DrawFn,
    config: Any = strategies.sampled_from(tests.data.TEST_CONFIGS).filter(  # noqa: B008
        tests.data.is_smudgable_vault_test_config
    ),
) -> Any:
    """Hypothesis strategy to replace falsy values with other falsy values.

    Uses [`_types.js_truthiness`][] internally, which is tested
    separately by
    [`tests.test_derivepassphrase_types.test_100_js_truthiness`][].

    Args:
        draw:
            The `draw` function, as provided for by hypothesis.
        config:
            A strategy which generates [`VaultTestConfig`][] objects.

    Returns:
        A new [`VaultTestConfig`][] where some falsy values have been
        replaced or added.

    """

    falsy = (None, False, 0, 0.0, "", float("nan"))
    falsy_no_str = (None, False, 0, 0.0, float("nan"))
    falsy_no_zero = (None, False, "", float("nan"))
    conf = draw(config)
    hypothesis.assume(tests.data.is_smudgable_vault_test_config(conf))
    obj = copy.deepcopy(conf.config)
    services: list[dict[str, Any]] = list(obj["services"].values())
    if "global" in obj:
        services.append(obj["global"])
    assert all(isinstance(x, dict) for x in services), (
        "is_smudgable_vault_test_config guard failed to "
        "ensure each settings dict is a dict"
    )
    for service in services:
        for key in ("phrase",):
            value = service.get(key)
            if not _types.js_truthiness(value) and value != "":
                service[key] = draw(strategies.sampled_from(falsy_no_str))
        for key in (
            "notes",
            "key",
            "length",
            "repeat",
        ):
            value = service.get(key)
            if not _types.js_truthiness(value):
                service[key] = draw(strategies.sampled_from(falsy))
        for key in (
            "lower",
            "upper",
            "number",
            "space",
            "dash",
            "symbol",
        ):
            value = service.get(key)
            if not _types.js_truthiness(value) and value != 0:
                service[key] = draw(strategies.sampled_from(falsy_no_zero))
    hypothesis.assume(obj != conf.config)
    return tests.data.VaultTestConfig(obj, conf.comment, conf.validation_settings)
