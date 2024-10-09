# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import copy

import hypothesis
import pytest
from hypothesis import strategies
from typing_extensions import Any

import tests
from derivepassphrase import _types


@tests.hypothesis_settings_coverage_compatible
@hypothesis.given(
    value=strategies.one_of(
        strategies.recursive(
            strategies.one_of(
                strategies.none(),
                strategies.booleans(),
                strategies.integers(),
                strategies.floats(allow_nan=False, allow_infinity=False),
                strategies.text(max_size=100),
                strategies.binary(max_size=100),
            ),
            lambda s: strategies.one_of(
                strategies.frozensets(s, max_size=100),
                strategies.builds(
                    tuple, strategies.frozensets(s, max_size=100)
                ),
            ),
            max_leaves=8,
        ),
        strategies.recursive(
            strategies.one_of(
                strategies.none(),
                strategies.booleans(),
                strategies.integers(),
                strategies.floats(allow_nan=False, allow_infinity=False),
                strategies.text(max_size=100),
                strategies.binary(max_size=100),
            ),
            lambda s: strategies.one_of(
                strategies.lists(s, max_size=100),
                strategies.dictionaries(strategies.text(max_size=100), s),
            ),
            max_leaves=25,
        ),
        strategies.builds(tuple),
        strategies.builds(list),
        strategies.builds(dict),
        strategies.builds(set),
        strategies.builds(frozenset),
    ),
)
def test_100_js_truthiness(value: Any) -> None:
    expected = (
        value is not None  # noqa: PLR1714
        and value != False  # noqa: E712
        and value != 0
        and value != 0.0
        and value != ''
    )
    assert _types.js_truthiness(value) == expected


@pytest.mark.parametrize(
    'test_config',
    [
        conf
        for conf in tests.TEST_CONFIGS
        if conf.validation_settings in {None, (True, True)}
    ],
    ids=tests._test_config_ids,
)
def test_200_is_vault_config(test_config: tests.VaultTestConfig) -> None:
    obj, comment, _ = test_config
    obj = copy.deepcopy(obj)
    _types.clean_up_falsy_vault_config_values(obj)
    assert _types.is_vault_config(obj) == (not comment), (
        'failed to complain about: ' + comment
        if comment
        else 'failed on valid example'
    )


@tests.hypothesis_settings_coverage_compatible
@hypothesis.given(
    test_config=tests.smudged_vault_test_config(
        config=strategies.sampled_from(tests.TEST_CONFIGS).filter(
            tests.is_valid_test_config
        )
    )
)
def test_200a_is_vault_config_smudged(
    test_config: tests.VaultTestConfig,
) -> None:
    _obj, comment, _ = test_config
    obj = copy.deepcopy(_obj)
    did_cleanup = _types.clean_up_falsy_vault_config_values(obj)
    assert _types.is_vault_config(obj) == (not comment), (
        'failed to complain about: ' + comment
        if comment
        else 'failed on valid example'
    )
    assert did_cleanup is None or bool(did_cleanup) == (
        obj != _obj
    ), 'mismatched report on cleanup work'


@pytest.mark.parametrize(
    'test_config', tests.TEST_CONFIGS, ids=tests._test_config_ids
)
def test_400_validate_vault_config(test_config: tests.VaultTestConfig) -> None:
    obj, comment, validation_settings = test_config
    allow_unknown_settings, allow_derivepassphrase_extensions = (
        validation_settings or (True, True)
    )
    obj = copy.deepcopy(obj)
    _types.clean_up_falsy_vault_config_values(obj)
    if comment:
        with pytest.raises((TypeError, ValueError)):
            _types.validate_vault_config(
                obj,
                allow_unknown_settings=allow_unknown_settings,
                allow_derivepassphrase_extensions=allow_derivepassphrase_extensions,
            )
    else:
        try:
            _types.validate_vault_config(
                obj,
                allow_unknown_settings=allow_unknown_settings,
                allow_derivepassphrase_extensions=allow_derivepassphrase_extensions,
            )
        except (TypeError, ValueError) as exc:  # pragma: no cover
            assert not exc, 'failed to validate valid example'  # noqa: PT017


@tests.hypothesis_settings_coverage_compatible
@hypothesis.given(
    test_config=tests.smudged_vault_test_config(
        config=strategies.sampled_from(tests.TEST_CONFIGS).filter(
            tests.is_smudgable_vault_test_config
        )
    )
)
def test_400a_validate_vault_config_smudged(
    test_config: tests.VaultTestConfig,
) -> None:
    _obj, comment, validation_settings = test_config
    allow_unknown_settings, allow_derivepassphrase_extensions = (
        validation_settings or (True, True)
    )
    obj = copy.deepcopy(_obj)
    did_cleanup = _types.clean_up_falsy_vault_config_values(obj)
    if comment:
        with pytest.raises((TypeError, ValueError)):
            _types.validate_vault_config(
                obj,
                allow_unknown_settings=allow_unknown_settings,
                allow_derivepassphrase_extensions=allow_derivepassphrase_extensions,
            )
    else:
        try:
            _types.validate_vault_config(
                obj,
                allow_unknown_settings=allow_unknown_settings,
                allow_derivepassphrase_extensions=allow_derivepassphrase_extensions,
            )
        except (TypeError, ValueError) as exc:  # pragma: no cover
            assert not exc, 'failed to validate valid example'  # noqa: PT017
    assert did_cleanup is None or bool(did_cleanup) == (
        obj != _obj
    ), 'mismatched report on cleanup work'
