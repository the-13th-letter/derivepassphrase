# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest
from typing_extensions import Any

from derivepassphrase import _types


@pytest.mark.parametrize(
    ['obj', 'comment'],
    [
        (None, 'not a dict'),
        ({}, 'missing required keys'),
        ({'global': None, 'services': {}}, 'bad config value: global'),
        (
            {'global': {'key': 123}, 'services': {}},
            'bad config value: global.key',
        ),
        (
            {'global': {'phrase': 'abc', 'key': '...'}, 'services': {}},
            'incompatible config values: global.key and global.phrase',
        ),
        ({'services': None}, 'bad config value: services'),
        ({'services': {2: {}}}, 'bad config value: services."2"'),
        ({'services': {'2': 2}}, 'bad config value: services."2"'),
        (
            {'services': {'sv': {'notes': False}}},
            'bad config value: services.sv.notes',
        ),
        ({'services': {'sv': {'notes': 'blah blah blah'}}}, ''),
        (
            {'services': {'sv': {'length': '200'}}},
            'bad config value: services.sv.length',
        ),
        (
            {'services': {'sv': {'length': 0.5}}},
            'bad config value: services.sv.length',
        ),
        (
            {'services': {'sv': {'length': -10}}},
            'bad config value: services.sv.length',
        ),
        (
            {'services': {'sv': {'lower': '10'}}},
            'bad config value: services.sv.lower',
        ),
        (
            {'services': {'sv': {'upper': -10}}},
            'bad config value: services.sv.upper',
        ),
        (
            {
                'global': {'phrase': 'my secret phrase'},
                'services': {'sv': {'length': 10}},
            },
            '',
        ),
        ({'services': {'sv': {'length': 10, 'phrase': '...'}}}, ''),
        ({'services': {'sv': {'length': 10, 'key': '...'}}}, ''),
        ({'services': {'sv': {'upper': 10, 'key': '...'}}}, ''),
        (
            {'services': {'sv': {'phrase': 'abc', 'key': '...'}}},
            'incompatible config values: services.sv.key and services.sv.phrase',  # noqa: E501
        ),
        (
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'phrase': 'abc', 'length': 10}},
            },
            '',
        ),
        (
            {
                'global': {'key': '...'},
                'services': {'sv': {'phrase': 'abc', 'length': 10}},
            },
            '',
        ),
        (
            {
                'global': {'key': '...'},
                'services': {
                    'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                    'sv2': {'length': 10, 'repeat': 1, 'lower': 1},
                },
            },
            '',
        ),
        (
            {
                'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
                'services': {
                    'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                    'sv2': {'length': 10, 'repeat': 1, 'lower': 1},
                },
            },
            '',
        ),
        (
            {
                'global': {'key': '...', 'unicode_normalization_form': None},
                'services': {},
            },
            'bad config value: global.unicode_normalization_form',
        ),
        (
            {
                'global': {'key': '...', 'unknown_key': None},
                'services': {
                    'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                    'sv2': {'length': 10, 'repeat': 1, 'lower': 1},
                },
            },
            '',
        ),
        (
            {
                'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
                'services': {
                    'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                    'sv2': {
                        'length': 10,
                        'repeat': 1,
                        'lower': 1,
                        'unknown_key': None,
                    },
                },
            },
            '',
        ),
    ],
)
def test_200_is_vault_config(obj: Any, comment: str) -> None:
    is_vault_config = _types.is_vault_config
    assert is_vault_config(obj) == (not comment), (
        'failed to complain about: ' + comment
        if comment
        else 'failed on valid example'
    )


@pytest.mark.parametrize(
    ['obj', 'allow_unknown_settings', 'allow_derivepassphrase_extensions'],
    [
        (
            {
                'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
                'services': {
                    'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                    'sv2': {'length': 10, 'repeat': 1, 'lower': 1},
                },
            },
            False,
            False,
        ),
        (
            {
                'global': {'key': '...', 'unknown_key': None},
                'services': {
                    'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                    'sv2': {'length': 10, 'repeat': 1, 'lower': 1},
                },
            },
            False,
            False,
        ),
        (
            {
                'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
                'services': {
                    'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                    'sv2': {
                        'length': 10,
                        'repeat': 1,
                        'lower': 1,
                        'unknown_key': None,
                    },
                },
            },
            False,
            False,
        ),
        (
            {
                'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
                'services': {
                    'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                    'sv2': {
                        'length': 10,
                        'repeat': 1,
                        'lower': 1,
                        'unknown_key': None,
                    },
                },
            },
            False,
            True,
        ),
        (
            {
                'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
                'services': {
                    'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                    'sv2': {
                        'length': 10,
                        'repeat': 1,
                        'lower': 1,
                        'unknown_key': None,
                    },
                },
            },
            True,
            False,
        ),
    ],
)
def test_400_validate_vault_config(
    obj: Any,
    allow_unknown_settings: bool,
    allow_derivepassphrase_extensions: bool,
) -> None:
    with pytest.raises((TypeError, ValueError), match='vault config '):
        _types.validate_vault_config(
            obj,
            allow_unknown_settings=allow_unknown_settings,
            allow_derivepassphrase_extensions=allow_derivepassphrase_extensions,
        )
