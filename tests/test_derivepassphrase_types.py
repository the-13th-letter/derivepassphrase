# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import copy
import math
import types

import hypothesis
import pytest
from hypothesis import strategies
from typing_extensions import Any

import tests
from derivepassphrase import _types


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


class Parametrize(types.SimpleNamespace):
    VALID_VAULT_TEST_CONFIGS = pytest.mark.parametrize(
        'test_config',
        [
            conf
            for conf in tests.TEST_CONFIGS
            if conf.validation_settings in {None, (True,)}
        ],
        ids=tests._test_config_ids,
    )
    VAULT_TEST_CONFIGS = pytest.mark.parametrize(
        'test_config', tests.TEST_CONFIGS, ids=tests._test_config_ids
    )


@hypothesis.given(value=js_nested_strategy())
@hypothesis.example(float('nan'))
def test_100_js_truthiness(value: Any) -> None:
    """Determine the truthiness of a value according to JavaScript.

    Use hypothesis to generate test values.

    """
    expected = (
        value is not None  # noqa: PLR1714
        and value != False  # noqa: E712
        and value != 0
        and value != 0.0
        and value != ''
        and not (isinstance(value, float) and math.isnan(value))
    )
    assert _types.js_truthiness(value) == expected


@Parametrize.VALID_VAULT_TEST_CONFIGS
def test_200_is_vault_config(test_config: tests.VaultTestConfig) -> None:
    """Is this vault configuration recognized as valid/invalid?

    Check all test configurations that do not need custom validation
    settings.

    This primarily tests the [`_types.is_vault_config`][] and
    [`_types.clean_up_falsy_vault_config_values`][] functions.

    """
    obj, comment, _ = test_config
    obj = copy.deepcopy(obj)
    _types.clean_up_falsy_vault_config_values(obj)
    assert _types.is_vault_config(obj) == (not comment), (
        'failed to complain about: ' + comment
        if comment
        else 'failed on valid example'
    )


@hypothesis.given(
    test_config=tests.smudged_vault_test_config(
        config=strategies.sampled_from([
            conf
            for conf in tests.TEST_CONFIGS
            if tests.is_valid_test_config(conf)
        ])
    )
)
def test_200a_is_vault_config_smudged(
    test_config: tests.VaultTestConfig,
) -> None:
    """Is this vault configuration recognized as valid/invalid?

    Generate test data via hypothesis by smudging all valid test
    configurations.

    This primarily tests the [`_types.is_vault_config`][] and
    [`_types.clean_up_falsy_vault_config_values`][] functions.

    """
    obj_, comment, _ = test_config
    obj = copy.deepcopy(obj_)
    did_cleanup = _types.clean_up_falsy_vault_config_values(obj)
    assert _types.is_vault_config(obj) == (not comment), (
        'failed to complain about: ' + comment
        if comment
        else 'failed on valid example'
    )
    assert did_cleanup is None or bool(did_cleanup) == (obj != obj_), (
        'mismatched report on cleanup work'
    )


@Parametrize.VAULT_TEST_CONFIGS
def test_400_validate_vault_config(test_config: tests.VaultTestConfig) -> None:
    """Validate this vault configuration.

    Check all test configurations, including those with non-standard
    validation settings.

    This primarily tests the [`_types.validate_vault_config`][] and
    [`_types.clean_up_falsy_vault_config_values`][] functions.

    """
    obj, comment, validation_settings = test_config
    (allow_unknown_settings,) = validation_settings or (True,)
    obj = copy.deepcopy(obj)
    _types.clean_up_falsy_vault_config_values(obj)
    if comment:
        with pytest.raises((TypeError, ValueError)):
            _types.validate_vault_config(
                obj,
                allow_unknown_settings=allow_unknown_settings,
            )
    else:
        try:
            _types.validate_vault_config(
                obj,
                allow_unknown_settings=allow_unknown_settings,
            )
        except (TypeError, ValueError) as exc:  # pragma: no cover
            assert not exc, 'failed to validate valid example'  # noqa: PT017


@hypothesis.given(
    test_config=tests.smudged_vault_test_config(
        config=strategies.sampled_from([
            conf
            for conf in tests.TEST_CONFIGS
            if tests.is_smudgable_vault_test_config(conf)
        ])
    )
)
def test_400a_validate_vault_config_smudged(
    test_config: tests.VaultTestConfig,
) -> None:
    """Validate this vault configuration.

    Generate test data via hypothesis by smudging all smudgable test
    configurations.

    This primarily tests the [`_types.validate_vault_config`][] and
    [`_types.clean_up_falsy_vault_config_values`][] functions.

    """
    obj_, comment, validation_settings = test_config
    (allow_unknown_settings,) = validation_settings or (True,)
    obj = copy.deepcopy(obj_)
    did_cleanup = _types.clean_up_falsy_vault_config_values(obj)
    if comment:
        with pytest.raises((TypeError, ValueError)):
            _types.validate_vault_config(
                obj,
                allow_unknown_settings=allow_unknown_settings,
            )
    else:
        try:
            _types.validate_vault_config(
                obj,
                allow_unknown_settings=allow_unknown_settings,
            )
        except (TypeError, ValueError) as exc:  # pragma: no cover
            assert not exc, 'failed to validate valid example'  # noqa: PT017
    assert did_cleanup is None or bool(did_cleanup) == (obj != obj_), (
        'mismatched report on cleanup work'
    )
