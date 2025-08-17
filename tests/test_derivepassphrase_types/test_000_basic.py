# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import copy
import types

import hypothesis
import pytest
from hypothesis import strategies

from derivepassphrase import _types
from tests import data
from tests.machinery import hypothesis as hypothesis_machinery


class Strategies:
    VALID_VAULT_TEST_CONFIGS = tuple(
        conf for conf in data.TEST_CONFIGS if conf.is_valid()
    )
    SMUDGABLE_VAULT_TEST_CONFIGS = tuple(
        conf for conf in data.TEST_CONFIGS if conf.is_smudgable()
    )


class Parametrize(types.SimpleNamespace):
    VALID_VAULT_TEST_CONFIGS = pytest.mark.parametrize(
        "test_config",
        Strategies.VALID_VAULT_TEST_CONFIGS,
        ids=data.VaultTestConfig._test_id,
    )
    VAULT_TEST_CONFIGS = pytest.mark.parametrize(
        "test_config",
        data.TEST_CONFIGS,
        ids=data.VaultTestConfig._test_id,
    )


class TestVaultConfig:
    """Test `vault` configuration detection."""

    @staticmethod
    def _test(test_config: data.VaultTestConfig) -> None:
        config, comment, _ = test_config
        obj = copy.deepcopy(config)
        did_cleanup = _types.clean_up_falsy_vault_config_values(obj)
        assert _types.is_vault_config(obj) == (not comment), (
            "failed to complain about: " + comment
            if comment
            else "failed on valid example"
        )
        assert did_cleanup is None or bool(did_cleanup) == (obj != config), (
            "mismatched report on cleanup work"
        )

    @Parametrize.VALID_VAULT_TEST_CONFIGS
    def test_is_config(self, test_config: data.VaultTestConfig) -> None:
        """Is this vault configuration recognized as valid/invalid?

        Check all test configurations that do not need custom validation
        settings.

        This primarily tests the [`_types.is_vault_config`][] and
        [`_types.clean_up_falsy_vault_config_values`][] functions.

        """
        self._test(test_config)

    @hypothesis.given(
        test_config=hypothesis_machinery.smudged_vault_test_config(
            config=strategies.sampled_from([
                conf for conf in data.TEST_CONFIGS if conf.is_valid()
            ])
        )
    )
    def test_is_config_even_if_smudged(
        self,
        test_config: data.VaultTestConfig,
    ) -> None:
        """Is this vault configuration recognized as valid/invalid?

        Generate test data via hypothesis by smudging all valid test
        configurations.

        This primarily tests the [`_types.is_vault_config`][] and
        [`_types.clean_up_falsy_vault_config_values`][] functions.

        """
        self._test(test_config)


class TestVaultConfigValidation:
    """Test the validation of `vault` configurations."""

    def _test(
        self,
        test_config: data.VaultTestConfig,
    ) -> None:
        config, comment, validation_settings = test_config
        (allow_unknown_settings,) = validation_settings or (True,)
        obj = copy.deepcopy(config)
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
            except (TypeError, ValueError):  # pragma: no cover
                pytest.fail("failed to validate valid example")
        assert did_cleanup is None or bool(did_cleanup) == (obj != config), (
            "mismatched report on cleanup work"
        )

    @Parametrize.VAULT_TEST_CONFIGS
    def test_validate_config(
        self,
        test_config: data.VaultTestConfig,
    ) -> None:
        """Validate this vault configuration.

        Check all test configurations, including those with non-standard
        validation settings.

        This primarily tests the [`_types.validate_vault_config`][] and
        [`_types.clean_up_falsy_vault_config_values`][] functions.

        """
        self._test(test_config)

    @hypothesis.given(
        test_config=hypothesis_machinery.smudged_vault_test_config(
            config=strategies.sampled_from([
                conf for conf in data.TEST_CONFIGS if conf.is_smudgable()
            ])
        )
    )
    def test_validate_config_even_if_smudged(
        self,
        test_config: data.VaultTestConfig,
    ) -> None:
        """Validate this vault configuration.

        Generate test data via hypothesis by smudging all smudgable test
        configurations.

        This primarily tests the [`_types.validate_vault_config`][] and
        [`_types.clean_up_falsy_vault_config_values`][] functions.

        """
        self._test(test_config)
