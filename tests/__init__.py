# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import base64
import contextlib
import copy
import enum
import importlib.util
import json
import os
import shlex
import stat
import sys
import tempfile
import zipfile
from typing import TYPE_CHECKING

import hypothesis
import pytest
from hypothesis import strategies
from typing_extensions import NamedTuple, Self, assert_never

from derivepassphrase import _types, cli, ssh_agent, vault

__all__ = ()

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    import click.testing
    from typing_extensions import Any, NotRequired, TypedDict

    class SSHTestKey(TypedDict):
        private_key: bytes
        private_key_blob: NotRequired[bytes]
        public_key: bytes | str
        public_key_data: bytes
        expected_signature: bytes | None
        derived_passphrase: bytes | str | None


class ValidationSettings(NamedTuple):
    allow_unknown_settings: bool
    allow_derivepassphrase_extensions: bool


class VaultTestConfig(NamedTuple):
    config: Any
    comment: str
    validation_settings: ValidationSettings | None


TEST_CONFIGS: list[VaultTestConfig] = [
    VaultTestConfig(None, 'not a dict', None),
    VaultTestConfig({}, 'missing required keys', None),
    VaultTestConfig(
        {'global': None, 'services': {}}, 'bad config value: global', None
    ),
    VaultTestConfig(
        {'global': {'key': 123}, 'services': {}},
        'bad config value: global.key',
        None,
    ),
    VaultTestConfig(
        {'global': {'phrase': 'abc', 'key': '...'}, 'services': {}},
        '',
        None,
    ),
    VaultTestConfig({'services': None}, 'bad config value: services', None),
    VaultTestConfig(
        {'services': {'1': {}, 2: {}}}, 'bad config value: services."2"', None
    ),
    VaultTestConfig(
        {'services': {'1': {}, '2': 2}}, 'bad config value: services."2"', None
    ),
    VaultTestConfig(
        {'services': {'sv': {'notes': ['sentinel', 'list']}}},
        'bad config value: services.sv.notes',
        None,
    ),
    VaultTestConfig(
        {'services': {'sv': {'notes': 'blah blah blah'}}}, '', None
    ),
    VaultTestConfig(
        {'services': {'sv': {'length': '200'}}},
        'bad config value: services.sv.length',
        None,
    ),
    VaultTestConfig(
        {'services': {'sv': {'length': 0.5}}},
        'bad config value: services.sv.length',
        None,
    ),
    VaultTestConfig(
        {'services': {'sv': {'length': ['sentinel', 'list']}}},
        'bad config value: services.sv.length',
        None,
    ),
    VaultTestConfig(
        {'services': {'sv': {'length': -10}}},
        'bad config value: services.sv.length',
        None,
    ),
    VaultTestConfig(
        {'services': {'sv': {'lower': '10'}}},
        'bad config value: services.sv.lower',
        None,
    ),
    VaultTestConfig(
        {'services': {'sv': {'upper': -10}}},
        'bad config value: services.sv.upper',
        None,
    ),
    VaultTestConfig(
        {'services': {'sv': {'number': ['sentinel', 'list']}}},
        'bad config value: services.sv.number',
        None,
    ),
    VaultTestConfig(
        {
            'global': {'phrase': 'my secret phrase'},
            'services': {'sv': {'length': 10}},
        },
        '',
        None,
    ),
    VaultTestConfig(
        {'services': {'sv': {'length': 10, 'phrase': '...'}}}, '', None
    ),
    VaultTestConfig(
        {'services': {'sv': {'length': 10, 'key': '...'}}}, '', None
    ),
    VaultTestConfig(
        {'services': {'sv': {'upper': 10, 'key': '...'}}}, '', None
    ),
    VaultTestConfig(
        {'services': {'sv': {'phrase': 'abc', 'key': '...'}}}, '', None
    ),
    VaultTestConfig(
        {
            'global': {'phrase': 'abc'},
            'services': {'sv': {'phrase': 'abc', 'length': 10}},
        },
        '',
        None,
    ),
    VaultTestConfig(
        {
            'global': {'key': '...'},
            'services': {'sv': {'phrase': 'abc', 'length': 10}},
        },
        '',
        None,
    ),
    VaultTestConfig(
        {
            'global': {'key': '...'},
            'services': {'sv': {'phrase': 'abc', 'key': '...', 'length': 10}},
        },
        '',
        None,
    ),
    VaultTestConfig(
        {
            'global': {'key': '...'},
            'services': {
                'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                'sv2': {'length': 10, 'repeat': 1, 'lower': 1},
            },
        },
        '',
        None,
    ),
    VaultTestConfig(
        {
            'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
            'services': {
                'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                'sv2': {'length': 10, 'repeat': 1, 'lower': 1},
            },
        },
        '',
        None,
    ),
    VaultTestConfig(
        {
            'global': {'key': '...', 'unicode_normalization_form': True},
            'services': {},
        },
        'bad config value: global.unicode_normalization_form',
        None,
    ),
    VaultTestConfig(
        {
            'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
            'services': {
                'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                'sv2': {'length': 10, 'repeat': 1, 'lower': 1},
            },
        },
        '',
        ValidationSettings(False, True),
    ),
    VaultTestConfig(
        {
            'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
            'services': {
                'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                'sv2': {'length': 10, 'repeat': 1, 'lower': 1},
            },
        },
        'extension key: .global.unicode_normalization_form',
        ValidationSettings(False, False),
    ),
    VaultTestConfig(
        {
            'global': {'key': '...', 'unknown_key': True},
            'services': {
                'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                'sv2': {'length': 10, 'repeat': 1, 'lower': 1},
            },
        },
        '',
        ValidationSettings(True, False),
    ),
    VaultTestConfig(
        {
            'global': {'key': '...', 'unknown_key': True},
            'services': {
                'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                'sv2': {'length': 10, 'repeat': 1, 'lower': 1},
            },
        },
        'unknown key: .global.unknown_key',
        ValidationSettings(False, False),
    ),
    VaultTestConfig(
        {
            'global': {'key': '...'},
            'services': {
                'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                'sv2': {
                    'length': 10,
                    'repeat': 1,
                    'lower': 1,
                    'unknown_key': True,
                },
            },
        },
        'unknown_key: .services.sv2.unknown_key',
        ValidationSettings(False, False),
    ),
    VaultTestConfig(
        {
            'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
            'services': {
                'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                'sv2': {
                    'length': 10,
                    'repeat': 1,
                    'lower': 1,
                    'unknown_key': True,
                },
            },
        },
        '',
        ValidationSettings(True, True),
    ),
    VaultTestConfig(
        {
            'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
            'services': {
                'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                'sv2': {
                    'length': 10,
                    'repeat': 1,
                    'lower': 1,
                    'unknown_key': True,
                },
            },
        },
        (
            'extension key (permitted): .global.unicode_normalization_form; '
            'unknown key: .services.sv2.unknown_key'
        ),
        ValidationSettings(False, True),
    ),
    VaultTestConfig(
        {
            'global': {'key': '...', 'unicode_normalization_form': 'NFC'},
            'services': {
                'sv1': {'phrase': 'abc', 'length': 10, 'upper': 1},
                'sv2': {
                    'length': 10,
                    'repeat': 1,
                    'lower': 1,
                    'unknown_key': True,
                },
            },
        },
        (
            'unknown key (permitted): .services.sv2.unknown_key; '
            'extension key: .global.unicode_normalization_form'
        ),
        ValidationSettings(True, False),
    ),
]


def is_valid_test_config(conf: VaultTestConfig, /) -> bool:
    """Return true if the test config is valid.

    Args:
        conf: The test config to check.

    """
    return not conf.comment and conf.validation_settings in {
        None,
        (True, True),
    }


def _test_config_ids(val: VaultTestConfig) -> Any:  # pragma: no cover
    """pytest id function for VaultTestConfig objects."""
    assert isinstance(val, VaultTestConfig)
    return val[1] or (val[0], val[1], val[2])


@strategies.composite
def vault_full_service_config(draw: strategies.DrawFn) -> dict[str, int]:
    lower = draw(strategies.integers(min_value=0, max_value=10))
    upper = draw(strategies.integers(min_value=0, max_value=10))
    number = draw(strategies.integers(min_value=0, max_value=10))
    space = draw(strategies.integers(min_value=0, max_value=10))
    dash = draw(strategies.integers(min_value=0, max_value=10))
    symbol = draw(strategies.integers(min_value=0, max_value=10))
    repeat = draw(strategies.integers(min_value=0, max_value=10))
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
        'lower': lower,
        'upper': upper,
        'number': number,
        'space': space,
        'dash': dash,
        'symbol': symbol,
        'repeat': repeat,
        'length': length,
    }


def is_smudgable_vault_test_config(conf: VaultTestConfig) -> bool:
    """Check whether this vault test config can be effectively smudged.

    A "smudged" test config is one where falsy values (in the JavaScript
    sense) can be replaced by other falsy values without changing the
    meaning of the config.

    Args:
        conf: A test config to check.

    Returns:
        True if the test config can be smudged, False otherwise.

    """
    config = conf.config
    return bool(
        isinstance(config, dict)
        and ('global' not in config or isinstance(config['global'], dict))
        and ('services' in config and isinstance(config['services'], dict))
        and all(isinstance(x, dict) for x in config['services'].values())
        and (config['services'] or config.get('global'))
    )


@strategies.composite
def smudged_vault_test_config(
    draw: strategies.DrawFn,
    config: Any = strategies.sampled_from(TEST_CONFIGS).filter(  # noqa: B008
        is_smudgable_vault_test_config
    ),
) -> Any:
    """Hypothesis strategy to replace falsy values with other falsy values.

    Uses [`_types.js_truthiness`][] internally, which is tested
    separately by
    [`tests.test_derivepassphrase_types.test_100_js_truthiness`][].

    Args:
        draw:
            The hypothesis draw function.
        config:
            A strategy which generates [`VaultTestConfig`][] objects.

    Returns:
        A new [`VaultTestConfig`][] where some falsy values have been
        replaced or added.

    """

    falsy = (None, False, 0, 0.0, '', float('nan'))
    falsy_no_str = (None, False, 0, 0.0, float('nan'))
    falsy_no_zero = (None, False, '', float('nan'))
    conf = draw(config)
    hypothesis.assume(is_smudgable_vault_test_config(conf))
    obj = copy.deepcopy(conf.config)
    services: list[dict[str, Any]] = list(obj['services'].values())
    if 'global' in obj:
        services.append(obj['global'])
    assert all(isinstance(x, dict) for x in services), (
        'is_smudgable_vault_test_config guard failed to '
        'ensure each setings dict is a dict'
    )
    for service in services:
        for key in ('phrase',):
            value = service.get(key)
            if not _types.js_truthiness(value) and value != '':
                service[key] = draw(strategies.sampled_from(falsy_no_str))
        for key in (
            'notes',
            'key',
            'length',
            'repeat',
        ):
            value = service.get(key)
            if not _types.js_truthiness(value):
                service[key] = draw(strategies.sampled_from(falsy))
        for key in (
            'lower',
            'upper',
            'number',
            'space',
            'dash',
            'symbol',
        ):
            value = service.get(key)
            if not _types.js_truthiness(value) and value != 0:
                service[key] = draw(strategies.sampled_from(falsy_no_zero))
    hypothesis.assume(obj != conf.config)
    return VaultTestConfig(obj, conf.comment, conf.validation_settings)


class KnownSSHAgent(str, enum.Enum):
    UNKNOWN: str = '(unknown)'
    Pageant: str = 'Pageant'
    OpenSSHAgent: str = 'OpenSSHAgent'


class SpawnedSSHAgentInfo(NamedTuple):
    agent_type: KnownSSHAgent
    client: ssh_agent.SSHAgentClient
    isolated: bool


class RunningSSHAgentInfo(NamedTuple):
    socket: str
    agent_type: KnownSSHAgent


SUPPORTED_KEYS: Mapping[str, SSHTestKey] = {
    'ed25519': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCBeIFoJtYCSF8P/zJIb+TBMIncHGpFBgnpCQ/7whJpdgAAAKDweO7H8Hju
xwAAAAtzc2gtZWQyNTUxOQAAACCBeIFoJtYCSF8P/zJIb+TBMIncHGpFBgnpCQ/7whJpdg
AAAEAbM/A869nkWZbe2tp3Dm/L6gitvmpH/aRZt8sBII3ExYF4gWgm1gJIXw//Mkhv5MEw
idwcakUGCekJD/vCEml2AAAAG3Rlc3Qga2V5IHdpdGhvdXQgcGFzc3BocmFzZQEC
-----END OPENSSH PRIVATE KEY-----
""",
        'private_key_blob': bytes.fromhex("""
            00 00 00 0b 73 73 68 2d 65 64 32 35 35 31 39
            00 00 00 20
            81 78 81 68 26 d6 02 48 5f 0f ff 32 48 6f e4 c1
            30 89 dc 1c 6a 45 06 09 e9 09 0f fb c2 12 69 76
            00 00 00 40
            1b 33 f0 3c eb d9 e4 59 96 de da da 77 0e 6f cb
            ea 08 ad be 6a 47 fd a4 59 b7 cb 01 20 8d c4 c5
            81 78 81 68 26 d6 02 48 5f 0f ff 32 48 6f e4 c1
            30 89 dc 1c 6a 45 06 09 e9 09 0f fb c2 12 69 76
            00 00 00 1b 74 65 73 74 20 6b 65 79 20 77 69 74
            68 6f 75 74 20 70 61 73 73 70 68 72 61 73 65
"""),
        'public_key': rb"""ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIF4gWgm1gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2 test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 0b 73 73 68 2d 65 64 32 35 35 31 39
            00 00 00 20
            81 78 81 68 26 d6 02 48 5f 0f ff 32 48 6f e4 c1
            30 89 dc 1c 6a 45 06 09 e9 09 0f fb c2 12 69 76
"""),
        'expected_signature': bytes.fromhex("""
            00 00 00 0b 73 73 68 2d 65 64 32 35 35 31 39
            00 00 00 40
            f0 98 19 80 6c 1a 97 d5 26 03 6e cc e3 65 8f 86
            66 07 13 19 13 09 21 33 33 f9 e4 36 53 1d af fd
            0d 08 1f ec f8 73 9b 8c 5f 55 39 16 7c 53 54 2c
            1e 52 bb 30 ed 7f 89 e2 2f 69 51 55 d8 9e a6 02
        """),
        'derived_passphrase': rb'8JgZgGwal9UmA27M42WPhmYHExkTCSEzM/nkNlMdr/0NCB/s+HObjF9VORZ8U1QsHlK7MO1/ieIvaVFV2J6mAg==',  # noqa: E501
    },
    # Currently only supported by PuTTY (which is deficient in other
    # niceties of the SSH agent and the agent's client).
    'ed448': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAASgAAAAlz
c2gtZWQ0NDgAAAA54vZy009Wu8wExjvEb3hqtLz1GO/+d5vmGUbErWQ4AUO9mYLT
zHJHc2m4s+yWzP29Cc3EcxizLG8AAAAA8BdhfCcXYXwnAAAACXNzaC1lZDQ0OAAA
ADni9nLTT1a7zATGO8RveGq0vPUY7/53m+YZRsStZDgBQ72ZgtPMckdzabiz7JbM
/b0JzcRzGLMsbwAAAAByM7GIMRvWJB3YD6SIpAF2uudX4ozZe0X917wPwiBrs373
9TM1n94Nib6hrxGNmCk2iBQDe2KALPgA4vZy009Wu8wExjvEb3hqtLz1GO/+d5vm
GUbErWQ4AUO9mYLTzHJHc2m4s+yWzP29Cc3EcxizLG8AAAAAG3Rlc3Qga2V5IHdp
dGhvdXQgcGFzc3BocmFzZQECAwQFBgcICQ==
-----END OPENSSH PRIVATE KEY-----
""",
        'private_key_blob': bytes.fromhex("""
            00 00 00 09 73 73 68 2d 65 64 34 34 38
            00 00 00 39 e2 f6 72 d3 4f 56 bb cc 04
            c6 3b c4 6f 78 6a b4 bc f5 18 ef fe 77 9b e6 19
            46 c4 ad 64 38 01 43 bd 99 82 d3 cc 72 47 73 69
            b8 b3 ec 96 cc fd bd 09 cd c4 73 18 b3 2c 6f 00
            00 00 00 72 33 b1
            88 31 1b d6 24 1d d8 0f a4 88 a4 01 76 ba e7 57
            e2 8c d9 7b 45 fd d7 bc 0f c2 20 6b b3 7e f7 f5
            33 35 9f de 0d 89 be a1 af 11 8d 98 29 36 88 14
            03 7b 62 80 2c f8 00 e2 f6 72 d3 4f 56 bb cc 04
            c6 3b c4 6f 78 6a b4 bc f5 18 ef fe 77 9b e6 19
            46 c4 ad 64 38 01 43 bd 99 82 d3 cc 72 47 73 69
            b8 b3 ec 96 cc fd bd 09 cd c4 73 18 b3 2c 6f 00
            00 00 00 1b 74 65 73 74 20 6b 65 79 20 77 69
            74 68 6f 75 74 20 70 61 73 73 70 68 72 61 73 65
"""),
        'public_key': rb"""ssh-ed448 AAAACXNzaC1lZDQ0OAAAADni9nLTT1a7zATGO8RveGq0vPUY7/53m+YZRsStZDgBQ72ZgtPMckdzabiz7JbM/b0JzcRzGLMsbwA= test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 09 73 73 68 2d 65 64 34 34 38
            00 00 00 39 e2 f6 72 d3 4f 56 bb cc 04
            c6 3b c4 6f 78 6a b4 bc f5 18 ef fe 77 9b e6 19
            46 c4 ad 64 38 01 43 bd 99 82 d3 cc 72 47 73 69
            b8 b3 ec 96 cc fd bd 09 cd c4 73 18 b3 2c 6f 00
        """),
        'expected_signature': bytes.fromhex("""
            00 00 00 09 73 73 68 2d 65 64 34 34 38
            00 00 00 72 06 86
            f4 64 a4 a6 ba d9 c3 22 c4 93 49 99 fc 11 de 67
            97 08 f2 d8 b7 3c 2c 13 e7 c5 1c 1e 92 a6 0e d8
            2f 6d 81 03 82 00 e3 72 e4 32 6d 72 d2 6d 32 84
            3f cc a9 1e 57 2c 00 9a b3 99 de 45 da ce 2e d1
            db e5 89 f3 35 be 24 58 90 c6 ca 04 f0 db 88 80
            db bd 77 7c 80 20 7f 3a 48 61 f6 1f ae a9 5e 53
            7b e0 9d 93 1e ea dc eb b5 cd 56 4c ea 8f 08 00
        """),
        'derived_passphrase': rb'Bob0ZKSmutnDIsSTSZn8Ed5nlwjy2Lc8LBPnxRwekqYO2C9tgQOCAONy5DJtctJtMoQ/zKkeVywAmrOZ3kXazi7R2+WJ8zW+JFiQxsoE8NuIgNu9d3yAIH86SGH2H66pXlN74J2THurc67XNVkzqjwgA',  # noqa: E501
    },
    'rsa': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAsaHu6Xs4cVsuDSNJlMCqoPVgmDgEviI8TfXmHKqX3JkIqI3LsvV7
Ijf8WCdTveEq7CkuZhImtsR52AOEVAoU8mDXDNr+nJ5wUPzf1UIaRjDe0lcXW4SlF01hQs
G4wYDuqxshwelraB/L3e0zhD7fjYHF8IbFsqGlFHWEwOtlfhhfbxJsTGguLm4A8/gdEJD5
2rkqDcZpIXCHtJbCzW9aQpWcs/PDw5ylwl/3dB7jfxyfrGz4O3QrzsqhWEsip97mOmwl6q
CHbq8V8x9zu89D/H+bG5ijqxhijbjcVUW3lZfw/97gy9J6rG31HNar5H8GycLTFwuCFepD
mTEpNgQLKoe8ePIEPq4WHhFUovBdwlrOByUKKqxreyvWt5gkpTARz+9Lt8OjBO3rpqK8sZ
VKH3sE3de2RJM3V9PJdmZSs2b8EFK3PsUGdlMPM9pn1uk4uIItKWBmooOynuD8Ll6aPwuW
AFn3l8nLLyWdrmmEYzHWXiRjQJxy1Bi5AbHMOWiPAAAFkDPkuBkz5LgZAAAAB3NzaC1yc2
EAAAGBALGh7ul7OHFbLg0jSZTAqqD1YJg4BL4iPE315hyql9yZCKiNy7L1eyI3/FgnU73h
KuwpLmYSJrbEedgDhFQKFPJg1wza/pyecFD839VCGkYw3tJXF1uEpRdNYULBuMGA7qsbIc
Hpa2gfy93tM4Q+342BxfCGxbKhpRR1hMDrZX4YX28SbExoLi5uAPP4HRCQ+dq5Kg3GaSFw
h7SWws1vWkKVnLPzw8OcpcJf93Qe438cn6xs+Dt0K87KoVhLIqfe5jpsJeqgh26vFfMfc7
vPQ/x/mxuYo6sYYo243FVFt5WX8P/e4MvSeqxt9RzWq+R/BsnC0xcLghXqQ5kxKTYECyqH
vHjyBD6uFh4RVKLwXcJazgclCiqsa3sr1reYJKUwEc/vS7fDowTt66aivLGVSh97BN3Xtk
STN1fTyXZmUrNm/BBStz7FBnZTDzPaZ9bpOLiCLSlgZqKDsp7g/C5emj8LlgBZ95fJyy8l
na5phGMx1l4kY0CcctQYuQGxzDlojwAAAAMBAAEAAAF/cNVYT+Om4x9+SItcz5bOByGIOj
yWUH8f9rRjnr5ILuwabIDgvFaVG+xM1O1hWADqzMnSEcknHRkTYEsqYPykAtxFvjOFEh70
6qRUJ+fVZkqRGEaI3oWyWKTOhcCIYImtONvb0LOv/HQ2H2AXCoeqjST1qr/xSuljBtcB8u
wxs3EqaO1yU7QoZpDcMX9plH7Rmc9nNfZcgrnktPk2deX2+Y/A5tzdVgG1IeqYp6CBMLNM
uhL0OPdDehgBoDujx+rhkZ1gpo1wcULIM94NL7VSHBPX0Lgh9T+3j1HVP+YnMAvhfOvfct
LlbJ06+TYGRAMuF2LPCAZM/m0FEyAurRgWxAjLXm+4kp2GAJXlw82deDkQ+P8cHNT6s9ZH
R5YSy3lpZ35594ZMOLR8KqVvhgJGF6i9019BiF91SDxjE+sp6dNGfN8W+64tHdDv2a0Mso
+8Qjyx7sTpi++EjLU8Iy73/e4B8qbXMyheyA/UUfgMtNKShh6sLlrD9h2Sm9RFTuEAAADA
Jh3u7WfnjhhKZYbAW4TsPNXDMrB0/t7xyAQgFmko7JfESyrJSLg1cO+QMOiDgD7zuQ9RSp
NIKdPsnIna5peh979mVjb2HgnikjyJECmBpLdwZKhX7MnIvgKw5lnQXHboEtWCa1N58l7f
srzwbi9pFUuUp9dShXNffmlUCjDRsVLbK5C6+iaIQyCWFYK8mc6dpNkIoPKf+Xg+EJCIFQ
oITqeu30Gc1+M+fdZc2ghq0b6XLthh/uHEry8b68M5KglMAAAAwQDw1i+IdcvPV/3u/q9O
/kzLpKO3tbT89sc1zhjZsDNjDAGluNr6n38iq/XYRZu7UTL9BG+EgFVfIUV7XsYT5e+BPf
13VS94rzZ7maCsOlULX+VdMO2zBucHIoec9RUlRZrfB21B2W7YGMhbpoa5lN3lKJQ7afHo
dXZUMp0cTFbOmbzJgSzO2/NE7BhVwmvcUzTDJGMMKuxBO6w99YKDKRKm0PNLFDz26rWm9L
dNS2MVfVuPMTpzT26HQG4pFageq9cAAADBALzRBXdZF8kbSBa5MTUBVTTzgKQm1C772gJ8
T01DJEXZsVtOv7mUC1/m/by6Hk4tPyvDBuGj9hHq4N7dPqGutHb1q5n0ADuoQjRW7BXw5Q
vC2EAD91xexdorIA5BgXU+qltBqzzBVzVtF7+jOZOjfzOlaTX9I5I5veyeTaTxZj1XXUzi
btBNdMEJJp7ifucYmoYAAwE7K+VlWagDEK2y8Mte9y9E+N0uO2j+h85sQt/UIb2iE/vhcg
Bgp6142WnSCQAAABt0ZXN0IGtleSB3aXRob3V0IHBhc3NwaHJhc2UB
-----END OPENSSH PRIVATE KEY-----
""",
        'private_key_blob': bytes.fromhex("""
            00 00 00 07 73 73 68 2d 72 73 61
            00 00 01 81 00
            b1 a1 ee e9 7b 38 71 5b 2e 0d 23 49 94 c0 aa a0
            f5 60 98 38 04 be 22 3c 4d f5 e6 1c aa 97 dc 99
            08 a8 8d cb b2 f5 7b 22 37 fc 58 27 53 bd e1 2a
            ec 29 2e 66 12 26 b6 c4 79 d8 03 84 54 0a 14 f2
            60 d7 0c da fe 9c 9e 70 50 fc df d5 42 1a 46 30
            de d2 57 17 5b 84 a5 17 4d 61 42 c1 b8 c1 80 ee
            ab 1b 21 c1 e9 6b 68 1f cb dd ed 33 84 3e df 8d
            81 c5 f0 86 c5 b2 a1 a5 14 75 84 c0 eb 65 7e 18
            5f 6f 12 6c 4c 68 2e 2e 6e 00 f3 f8 1d 10 90 f9
            da b9 2a 0d c6 69 21 70 87 b4 96 c2 cd 6f 5a 42
            95 9c b3 f3 c3 c3 9c a5 c2 5f f7 74 1e e3 7f 1c
            9f ac 6c f8 3b 74 2b ce ca a1 58 4b 22 a7 de e6
            3a 6c 25 ea a0 87 6e af 15 f3 1f 73 bb cf 43 fc
            7f 9b 1b 98 a3 ab 18 62 8d b8 dc 55 45 b7 95 97
            f0 ff de e0 cb d2 7a ac 6d f5 1c d6 ab e4 7f 06
            c9 c2 d3 17 0b 82 15 ea 43 99 31 29 36 04 0b 2a
            87 bc 78 f2 04 3e ae 16 1e 11 54 a2 f0 5d c2 5a
            ce 07 25 0a 2a ac 6b 7b 2b d6 b7 98 24 a5 30 11
            cf ef 4b b7 c3 a3 04 ed eb a6 a2 bc b1 95 4a 1f
            7b 04 dd d7 b6 44 93 37 57 d3 c9 76 66 52 b3 66
            fc 10 52 b7 3e c5 06 76 53 0f 33 da 67 d6 e9 38
            b8 82 2d 29 60 66 a2 83 b2 9e e0 fc 2e 5e 9a 3f
            0b 96 00 59 f7 97 c9 cb 2f 25 9d ae 69 84 63 31
            d6 5e 24 63 40 9c 72 d4 18 b9 01 b1 cc 39 68 8f
            00 00 00 03 01 00 01
            00 00 01 7f
            70 d5 58 4f e3 a6 e3 1f 7e 48 8b 5c cf 96 ce
            07 21 88 3a 3c 96 50 7f 1f f6 b4 63 9e be 48 2e
            ec 1a 6c 80 e0 bc 56 95 1b ec 4c d4 ed 61 58 00
            ea cc c9 d2 11 c9 27 1d 19 13 60 4b 2a 60 fc a4
            02 dc 45 be 33 85 12 1e f4 ea a4 54 27 e7 d5 66
            4a 91 18 46 88 de 85 b2 58 a4 ce 85 c0 88 60 89
            ad 38 db db d0 b3 af fc 74 36 1f 60 17 0a 87 aa
            8d 24 f5 aa bf f1 4a e9 63 06 d7 01 f2 ec 31 b3
            71 2a 68 ed 72 53 b4 28 66 90 dc 31 7f 69 94 7e
            d1 99 cf 67 35 f6 5c 82 b9 e4 b4 f9 36 75 e5 f6
            f9 8f c0 e6 dc dd 56 01 b5 21 ea 98 a7 a0 81 30
            b3 4c ba 12 f4 38 f7 43 7a 18 01 a0 3b a3 c7 ea
            e1 91 9d 60 a6 8d 70 71 42 c8 33 de 0d 2f b5 52
            1c 13 d7 d0 b8 21 f5 3f b7 8f 51 d5 3f e6 27 30
            0b e1 7c eb df 72 d2 e5 6c 9d 3a f9 36 06 44 03
            2e 17 62 cf 08 06 4c fe 6d 05 13 20 2e ad 18 16
            c4 08 cb 5e 6f b8 92 9d 86 00 95 e5 c3 cd 9d 78
            39 10 f8 ff 1c 1c d4 fa b3 d6 47 47 96 12 cb 79
            69 67 7e 79 f7 86 4c 38 b4 7c 2a a5 6f 86 02 46
            17 a8 bd d3 5f 41 88 5f 75 48 3c 63 13 eb 29 e9
            d3 46 7c df 16 fb ae 2d 1d d0 ef d9 ad 0c b2 8f
            bc 42 3c b1 ee c4 e9 8b ef 84 8c b5 3c 23 2e f7
            fd ee 01 f2 a6 d7 33 28 5e c8 0f d4 51 f8 0c b4
            d2 92 86 1e ac 2e 5a c3 f6 1d 92 9b d4 45 4e e1
            00 00 00 c0
            26 1d ee ed 67 e7 8e 18 4a 65 86 c0 5b 84 ec 3c
            d5 c3 32 b0 74 fe de f1 c8 04 20 16 69 28 ec 97
            c4 4b 2a c9 48 b8 35 70 ef 90 30 e8 83 80 3e f3
            b9 0f 51 4a 93 48 29 d3 ec 9c 89 da e6 97 a1 f7
            bf 66 56 36 f6 1e 09 e2 92 3c 89 10 29 81 a4 b7
            70 64 a8 57 ec c9 c8 be 02 b0 e6 59 d0 5c 76 e8
            12 d5 82 6b 53 79 f2 5e df b2 bc f0 6e 2f 69 15
            4b 94 a7 d7 52 85 73 5f 7e 69 54 0a 30 d1 b1 52
            db 2b 90 ba fa 26 88 43 20 96 15 82 bc 99 ce 9d
            a4 d9 08 a0 f2 9f f9 78 3e 10 90 88 15 0a 08 4e
            a7 ae df 41 9c d7 e3 3e 7d d6 5c da 08 6a d1 be
            97 2e d8 61 fe e1 c4 af 2f 1b eb c3 39 2a 09 4c
            00 00 00 c1 00
            f0 d6 2f 88 75 cb cf 57 fd ee fe af 4e fe 4c cb
            a4 a3 b7 b5 b4 fc f6 c7 35 ce 18 d9 b0 33 63 0c
            01 a5 b8 da fa 9f 7f 22 ab f5 d8 45 9b bb 51 32
            fd 04 6f 84 80 55 5f 21 45 7b 5e c6 13 e5 ef 81
            3d fd 77 55 2f 78 af 36 7b 99 a0 ac 3a 55 0b 5f
            e5 5d 30 ed b3 06 e7 07 22 87 9c f5 15 25 45 9a
            df 07 6d 41 d9 6e d8 18 c8 5b a6 86 b9 94 dd e5
            28 94 3b 69 f1 e8 75 76 54 32 9d 1c 4c 56 ce 99
            bc c9 81 2c ce db f3 44 ec 18 55 c2 6b dc 53 34
            c3 24 63 0c 2a ec 41 3b ac 3d f5 82 83 29 12 a6
            d0 f3 4b 14 3c f6 ea b5 a6 f4 b7 4d 4b 63 15 7d
            5b 8f 31 3a 73 4f 6e 87 40 6e 29 15 a8 1e ab d7
            00 00 00 c1 00
            bc d1 05 77 59 17 c9 1b 48 16 b9 31 35 01 55 34
            f3 80 a4 26 d4 2e fb da 02 7c 4f 4d 43 24 45 d9
            b1 5b 4e bf b9 94 0b 5f e6 fd bc ba 1e 4e 2d 3f
            2b c3 06 e1 a3 f6 11 ea e0 de dd 3e a1 ae b4 76
            f5 ab 99 f4 00 3b a8 42 34 56 ec 15 f0 e5 0b c2
            d8 40 03 f7 5c 5e c5 da 2b 20 0e 41 81 75 3e aa
            5b 41 ab 3c c1 57 35 6d 17 bf a3 39 93 a3 7f 33
            a5 69 35 fd 23 92 39 bd ec 9e 4d a4 f1 66 3d 57
            5d 4c e2 6e d0 4d 74 c1 09 26 9e e2 7e e7 18 9a
            86 00 03 01 3b 2b e5 65 59 a8 03 10 ad b2 f0 cb
            5e f7 2f 44 f8 dd 2e 3b 68 fe 87 ce 6c 42 df d4
            21 bd a2 13 fb e1 72 00 60 a7 ad 78 d9 69 d2 09
            00 00 00 1b 74 65 73 74 20 6b 65 79 20 77 69
            74 68 6f 75 74 20 70 61 73 73 70 68 72 61 73 65
"""),
        'public_key': rb"""ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCxoe7pezhxWy4NI0mUwKqg9WCYOAS+IjxN9eYcqpfcmQiojcuy9XsiN/xYJ1O94SrsKS5mEia2xHnYA4RUChTyYNcM2v6cnnBQ/N/VQhpGMN7SVxdbhKUXTWFCwbjBgO6rGyHB6WtoH8vd7TOEPt+NgcXwhsWyoaUUdYTA62V+GF9vEmxMaC4ubgDz+B0QkPnauSoNxmkhcIe0lsLNb1pClZyz88PDnKXCX/d0HuN/HJ+sbPg7dCvOyqFYSyKn3uY6bCXqoIdurxXzH3O7z0P8f5sbmKOrGGKNuNxVRbeVl/D/3uDL0nqsbfUc1qvkfwbJwtMXC4IV6kOZMSk2BAsqh7x48gQ+rhYeEVSi8F3CWs4HJQoqrGt7K9a3mCSlMBHP70u3w6ME7eumoryxlUofewTd17ZEkzdX08l2ZlKzZvwQUrc+xQZ2Uw8z2mfW6Ti4gi0pYGaig7Ke4PwuXpo/C5YAWfeXycsvJZ2uaYRjMdZeJGNAnHLUGLkBscw5aI8= test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 07 73 73 68 2d 72 73 61
            00 00 00 03 01 00 01
            00 00 01 81 00
            b1 a1 ee e9 7b 38 71 5b 2e 0d 23 49 94 c0 aa a0
            f5 60 98 38 04 be 22 3c 4d f5 e6 1c aa 97 dc 99
            08 a8 8d cb b2 f5 7b 22 37 fc 58 27 53 bd e1 2a
            ec 29 2e 66 12 26 b6 c4 79 d8 03 84 54 0a 14 f2
            60 d7 0c da fe 9c 9e 70 50 fc df d5 42 1a 46 30
            de d2 57 17 5b 84 a5 17 4d 61 42 c1 b8 c1 80 ee
            ab 1b 21 c1 e9 6b 68 1f cb dd ed 33 84 3e df 8d
            81 c5 f0 86 c5 b2 a1 a5 14 75 84 c0 eb 65 7e 18
            5f 6f 12 6c 4c 68 2e 2e 6e 00 f3 f8 1d 10 90 f9
            da b9 2a 0d c6 69 21 70 87 b4 96 c2 cd 6f 5a 42
            95 9c b3 f3 c3 c3 9c a5 c2 5f f7 74 1e e3 7f 1c
            9f ac 6c f8 3b 74 2b ce ca a1 58 4b 22 a7 de e6
            3a 6c 25 ea a0 87 6e af 15 f3 1f 73 bb cf 43 fc
            7f 9b 1b 98 a3 ab 18 62 8d b8 dc 55 45 b7 95 97
            f0 ff de e0 cb d2 7a ac 6d f5 1c d6 ab e4 7f 06
            c9 c2 d3 17 0b 82 15 ea 43 99 31 29 36 04 0b 2a
            87 bc 78 f2 04 3e ae 16 1e 11 54 a2 f0 5d c2 5a
            ce 07 25 0a 2a ac 6b 7b 2b d6 b7 98 24 a5 30 11
            cf ef 4b b7 c3 a3 04 ed eb a6 a2 bc b1 95 4a 1f
            7b 04 dd d7 b6 44 93 37 57 d3 c9 76 66 52 b3 66
            fc 10 52 b7 3e c5 06 76 53 0f 33 da 67 d6 e9 38
            b8 82 2d 29 60 66 a2 83 b2 9e e0 fc 2e 5e 9a 3f
            0b 96 00 59 f7 97 c9 cb 2f 25 9d ae 69 84 63 31
            d6 5e 24 63 40 9c 72 d4 18 b9 01 b1 cc 39 68 8f
"""),
        'expected_signature': bytes.fromhex("""
            00 00 00 07 73 73 68 2d 72 73 61
            00 00 01 80
            a2 10 7c 2e f6 bb 53 a8 74 2a a1 19 99 ad 81 be
            79 9c ed d6 9d 09 4e 6e c5 18 48 33 90 77 99 68
            f7 9e 03 5a cd 4e 18 eb 89 7d 85 a2 ee ae 4a 92
            f6 6f ce b9 fe 86 7f 2a 6b 31 da 6e 1a fe a2 a5
            88 b8 44 7f a1 76 73 b3 ec 75 b5 d0 a6 b9 15 97
            65 09 13 7d 94 21 d1 fb 5d 0f 8b 23 04 77 c2 c3
            55 22 b1 a0 09 8a f5 38 2a d6 7f 1b 87 29 a0 25
            d3 25 6f cb 64 61 07 98 dc 14 c5 84 f8 92 24 5e
            50 11 6b 49 e5 f0 cc 29 cb 29 a9 19 d8 a7 71 1f
            91 0b 05 b1 01 4b c2 5f 00 a5 b6 21 bf f8 2c 9d
            67 9b 47 3b 0a 49 6b 79 2d fc 1d ec 0c b0 e5 27
            22 d5 a9 f8 d3 c3 f9 df 48 68 e9 fb ef 3c dc 26
            bf cf ea 29 43 01 a6 e3 c5 51 95 f4 66 6d 8a 55
            e2 47 ec e8 30 45 4c ae 47 e7 c9 a4 21 8b 64 ba
            b6 88 f6 21 f8 73 b9 cb 11 a1 78 75 92 c6 5a e5
            64 fe ed 42 d9 95 99 e6 2b 6f 3c 16 3c 28 74 a4
            72 2f 0d 3f 2c 33 67 aa 35 19 8e e7 b5 11 2f b3
            f7 6a c5 02 e2 6f a3 42 e3 62 19 99 03 ea a5 20
            e7 a1 e3 bc c8 06 a3 b5 7c d6 76 5d df 6f 60 46
            83 2a 08 00 d6 d3 d9 a4 c1 41 8c f8 60 56 45 81
            da 3b a2 16 1f 9e 4e 75 83 17 da c3 53 c3 3e 19
            a4 1b bc d2 29 b8 78 61 2b 78 e6 b1 52 b0 d5 ec
            de 69 2c 48 62 d9 fd d1 9b 6b b0 49 db d3 ff 38
            e7 10 d9 2d ce 9f 0d 5e 09 7b 37 d2 7b c3 bf ce
"""),
        'derived_passphrase': rb'ohB8Lva7U6h0KqEZma2Bvnmc7dadCU5uxRhIM5B3mWj3ngNazU4Y64l9haLurkqS9m/Ouf6GfyprMdpuGv6ipYi4RH+hdnOz7HW10Ka5FZdlCRN9lCHR+10PiyMEd8LDVSKxoAmK9Tgq1n8bhymgJdMlb8tkYQeY3BTFhPiSJF5QEWtJ5fDMKcspqRnYp3EfkQsFsQFLwl8ApbYhv/gsnWebRzsKSWt5Lfwd7Ayw5Sci1an408P530ho6fvvPNwmv8/qKUMBpuPFUZX0Zm2KVeJH7OgwRUyuR+fJpCGLZLq2iPYh+HO5yxGheHWSxlrlZP7tQtmVmeYrbzwWPCh0pHIvDT8sM2eqNRmO57URL7P3asUC4m+jQuNiGZkD6qUg56HjvMgGo7V81nZd329gRoMqCADW09mkwUGM+GBWRYHaO6IWH55OdYMX2sNTwz4ZpBu80im4eGEreOaxUrDV7N5pLEhi2f3Rm2uwSdvT/zjnENktzp8NXgl7N9J7w7/O',  # noqa: E501
    },
}

UNSUITABLE_KEYS: Mapping[str, SSHTestKey] = {
    'dsa1024': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQC7KAZXqBGNVLBQPrcMYAoNW54BhD8aIhe7BDWYzJcsaMt72VKSkguZ8+XR7nRa
0C/ZsBi+uJp0dpxy9ZMTOWX4u5YPMeQcXEdGExZIfimGqSOAsy6fCld2IfJZJZExcCmhe9
Ssjsd3YSAPJRluOXFQc95MZoR5hMwlIDD8QzrE7QAAABUA99nOZOgd7aHMVGoXpUEBcn7H
ossAAACALr2Ag3hxM3rKdxzVUw8fX0VVPXO+3+Kr8hGe0Kc/7NwVaBVL1GQ8fenBuWynpA
UbH0wo3h1wkB/8hX6p+S8cnu5rIBlUuVNwLw/bIYohK98LfqTYK/V+g6KD+8m34wvEiXZm
qywY54n2bksch1Nqvj/tNpLzExSx/XS0kSM1aigAAACAbQNRPcVEuGDrEcf+xg5tgAejPX
BPXr/Jss+Chk64km3mirMYjAWyWYtVcgT+7hOYxtYRin8LyMLqKRmqa0Q5UrvDfChgLhvs
G9YSb/Mpw5qm8PiHSafwhkaz/te3+8hKogqoe7sd+tCF06IpJr5k70ACiNtRGqssNF8Elr
l1efYAAAH4swlfVrMJX1YAAAAHc3NoLWRzcwAAAIEAuygGV6gRjVSwUD63DGAKDVueAYQ/
GiIXuwQ1mMyXLGjLe9lSkpILmfPl0e50WtAv2bAYvriadHaccvWTEzll+LuWDzHkHFxHRh
MWSH4phqkjgLMunwpXdiHyWSWRMXApoXvUrI7Hd2EgDyUZbjlxUHPeTGaEeYTMJSAw/EM6
xO0AAAAVAPfZzmToHe2hzFRqF6VBAXJ+x6LLAAAAgC69gIN4cTN6yncc1VMPH19FVT1zvt
/iq/IRntCnP+zcFWgVS9RkPH3pwblsp6QFGx9MKN4dcJAf/IV+qfkvHJ7uayAZVLlTcC8P
2yGKISvfC36k2Cv1foOig/vJt+MLxIl2ZqssGOeJ9m5LHIdTar4/7TaS8xMUsf10tJEjNW
ooAAAAgG0DUT3FRLhg6xHH/sYObYAHoz1wT16/ybLPgoZOuJJt5oqzGIwFslmLVXIE/u4T
mMbWEYp/C8jC6ikZqmtEOVK7w3woYC4b7BvWEm/zKcOapvD4h0mn8IZGs/7Xt/vISqIKqH
u7HfrQhdOiKSa+ZO9AAojbURqrLDRfBJa5dXn2AAAAFQDJHfenj4EJ9WkehpdJatPBlqCW
0gAAABt0ZXN0IGtleSB3aXRob3V0IHBhc3NwaHJhc2UBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
""",
        'private_key_blob': bytes.fromhex("""
            00 00 00 07 73 73 68 2d 64 73 73
            00 00 00 81 00
            bb 28 06 57 a8 11 8d 54 b0 50 3e b7 0c 60 0a 0d
            5b 9e 01 84 3f 1a 22 17 bb 04 35 98 cc 97 2c 68
            cb 7b d9 52 92 92 0b 99 f3 e5 d1 ee 74 5a d0 2f
            d9 b0 18 be b8 9a 74 76 9c 72 f5 93 13 39 65 f8
            bb 96 0f 31 e4 1c 5c 47 46 13 16 48 7e 29 86 a9
            23 80 b3 2e 9f 0a 57 76 21 f2 59 25 91 31 70 29
            a1 7b d4 ac 8e c7 77 61 20 0f 25 19 6e 39 71 50
            73 de 4c 66 84 79 84 cc 25 20 30 fc 43 3a c4 ed
            00 00 00 15 00 f7 d9 ce 64
            e8 1d ed a1 cc 54 6a 17 a5 41 01 72 7e c7 a2 cb
            00 00 00 80
            2e bd 80 83 78 71 33 7a ca 77 1c d5 53 0f 1f 5f
            45 55 3d 73 be df e2 ab f2 11 9e d0 a7 3f ec dc
            15 68 15 4b d4 64 3c 7d e9 c1 b9 6c a7 a4 05 1b
            1f 4c 28 de 1d 70 90 1f fc 85 7e a9 f9 2f 1c 9e
            ee 6b 20 19 54 b9 53 70 2f 0f db 21 8a 21 2b df
            0b 7e a4 d8 2b f5 7e 83 a2 83 fb c9 b7 e3 0b c4
            89 76 66 ab 2c 18 e7 89 f6 6e 4b 1c 87 53 6a be
            3f ed 36 92 f3 13 14 b1 fd 74 b4 91 23 35 6a 28
            00 00 00 80
            6d 03 51 3d c5 44 b8 60 eb 11 c7 fe c6 0e 6d 80
            07 a3 3d 70 4f 5e bf c9 b2 cf 82 86 4e b8 92 6d
            e6 8a b3 18 8c 05 b2 59 8b 55 72 04 fe ee 13 98
            c6 d6 11 8a 7f 0b c8 c2 ea 29 19 aa 6b 44 39 52
            bb c3 7c 28 60 2e 1b ec 1b d6 12 6f f3 29 c3 9a
            a6 f0 f8 87 49 a7 f0 86 46 b3 fe d7 b7 fb c8 4a
            a2 0a a8 7b bb 1d fa d0 85 d3 a2 29 26 be 64 ef
            40 02 88 db 51 1a ab 2c 34 5f 04 96 b9 75 79 f6
            00 00 00 15 00 c9 1d f7 a7
            8f 81 09 f5 69 1e 86 97 49 6a d3 c1 96 a0 96 d2
            00 00 00 1b 74 65 73 74 20 6b 65 79 20 77 69
            74 68 6f 75 74 20 70 61 73 73 70 68 72 61 73 65
"""),
        'public_key': rb"""ssh-dss AAAAB3NzaC1kc3MAAACBALsoBleoEY1UsFA+twxgCg1bngGEPxoiF7sENZjMlyxoy3vZUpKSC5nz5dHudFrQL9mwGL64mnR2nHL1kxM5Zfi7lg8x5BxcR0YTFkh+KYapI4CzLp8KV3Yh8lklkTFwKaF71KyOx3dhIA8lGW45cVBz3kxmhHmEzCUgMPxDOsTtAAAAFQD32c5k6B3tocxUahelQQFyfseiywAAAIAuvYCDeHEzesp3HNVTDx9fRVU9c77f4qvyEZ7Qpz/s3BVoFUvUZDx96cG5bKekBRsfTCjeHXCQH/yFfqn5Lxye7msgGVS5U3AvD9shiiEr3wt+pNgr9X6DooP7ybfjC8SJdmarLBjnifZuSxyHU2q+P+02kvMTFLH9dLSRIzVqKAAAAIBtA1E9xUS4YOsRx/7GDm2AB6M9cE9ev8myz4KGTriSbeaKsxiMBbJZi1VyBP7uE5jG1hGKfwvIwuopGaprRDlSu8N8KGAuG+wb1hJv8ynDmqbw+IdJp/CGRrP+17f7yEqiCqh7ux360IXToikmvmTvQAKI21Eaqyw0XwSWuXV59g== test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 07 73 73 68 2d 64 73 73
            00 00 00 81 00
            bb 28 06 57 a8 11 8d 54 b0 50 3e b7 0c 60 0a 0d
            5b 9e 01 84 3f 1a 22 17 bb 04 35 98 cc 97 2c 68
            cb 7b d9 52 92 92 0b 99 f3 e5 d1 ee 74 5a d0 2f
            d9 b0 18 be b8 9a 74 76 9c 72 f5 93 13 39 65 f8
            bb 96 0f 31 e4 1c 5c 47 46 13 16 48 7e 29 86 a9
            23 80 b3 2e 9f 0a 57 76 21 f2 59 25 91 31 70 29
            a1 7b d4 ac 8e c7 77 61 20 0f 25 19 6e 39 71 50
            73 de 4c 66 84 79 84 cc 25 20 30 fc 43 3a c4 ed
            00 00 00 15 00 f7 d9 ce 64
            e8 1d ed a1 cc 54 6a 17 a5 41 01 72 7e c7 a2 cb
            00 00 00 80
            2e bd 80 83 78 71 33 7a ca 77 1c d5 53 0f 1f 5f
            45 55 3d 73 be df e2 ab f2 11 9e d0 a7 3f ec dc
            15 68 15 4b d4 64 3c 7d e9 c1 b9 6c a7 a4 05 1b
            1f 4c 28 de 1d 70 90 1f fc 85 7e a9 f9 2f 1c 9e
            ee 6b 20 19 54 b9 53 70 2f 0f db 21 8a 21 2b df
            0b 7e a4 d8 2b f5 7e 83 a2 83 fb c9 b7 e3 0b c4
            89 76 66 ab 2c 18 e7 89 f6 6e 4b 1c 87 53 6a be
            3f ed 36 92 f3 13 14 b1 fd 74 b4 91 23 35 6a 28
            00 00 00 80
            6d 03 51 3d c5 44 b8 60 eb 11 c7 fe c6 0e 6d 80
            07 a3 3d 70 4f 5e bf c9 b2 cf 82 86 4e b8 92 6d
            e6 8a b3 18 8c 05 b2 59 8b 55 72 04 fe ee 13 98
            c6 d6 11 8a 7f 0b c8 c2 ea 29 19 aa 6b 44 39 52
            bb c3 7c 28 60 2e 1b ec 1b d6 12 6f f3 29 c3 9a
            a6 f0 f8 87 49 a7 f0 86 46 b3 fe d7 b7 fb c8 4a
            a2 0a a8 7b bb 1d fa d0 85 d3 a2 29 26 be 64 ef
            40 02 88 db 51 1a ab 2c 34 5f 04 96 b9 75 79 f6
"""),
        'expected_signature': None,
        'derived_passphrase': None,
    },
    'ecdsa256': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTLbU0zDwsk2Dvp+VYIrsNVf5gWwz2S
3SZ8TbxiQRkpnGSVqyIoHJOJc+NQItAa7xlJ/8Z6gfz57Z3apUkaMJm6AAAAuKeY+YinmP
mIAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMttTTMPCyTYO+n5
Vgiuw1V/mBbDPZLdJnxNvGJBGSmcZJWrIigck4lz41Ai0BrvGUn/xnqB/PntndqlSRowmb
oAAAAhAKIl/3n0pKVIxpZkXTGtii782Qr4yIcvHdpxjO/QsIqKAAAAG3Rlc3Qga2V5IHdp
dGhvdXQgcGFzc3BocmFzZQECAwQ=
-----END OPENSSH PRIVATE KEY-----
""",
        'private_key_blob': bytes.fromhex("""
            00 00 00 13 65 63 64
            73 61 2d 73 68 61 32 2d 6e 69 73 74 70 32 35 36
            00 00 00 08 6e 69 73 74 70 32 35 36
            00 00 00 41 04
            cb 6d 4d 33 0f 0b 24 d8 3b e9 f9 56 08 ae c3 55
            7f 98 16 c3 3d 92 dd 26 7c 4d bc 62 41 19 29 9c
            64 95 ab 22 28 1c 93 89 73 e3 50 22 d0 1a ef 19
            49 ff c6 7a 81 fc f9 ed 9d da a5 49 1a 30 99 ba
            00 00 00 21 00
            a2 25 ff 79 f4 a4 a5 48 c6 96 64 5d 31 ad 8a 2e
            fc d9 0a f8 c8 87 2f 1d da 71 8c ef d0 b0 8a 8a
            00 00 00 1b 74 65 73 74 20 6b 65 79 20 77 69
            74 68 6f 75 74 20 70 61 73 73 70 68 72 61 73 65
"""),
        'public_key': rb"""ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMttTTMPCyTYO+n5Vgiuw1V/mBbDPZLdJnxNvGJBGSmcZJWrIigck4lz41Ai0BrvGUn/xnqB/PntndqlSRowmbo= test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 13 65 63 64
            73 61 2d 73 68 61 32 2d 6e 69 73 74 70 32 35 36
            00 00 00 08 6e 69 73 74 70 32 35 36
            00 00 00 41 04
            cb 6d 4d 33 0f 0b 24 d8 3b e9 f9 56 08 ae c3 55
            7f 98 16 c3 3d 92 dd 26 7c 4d bc 62 41 19 29 9c
            64 95 ab 22 28 1c 93 89 73 e3 50 22 d0 1a ef 19
            49 ff c6 7a 81 fc f9 ed 9d da a5 49 1a 30 99 ba
"""),
        'expected_signature': None,
        'derived_passphrase': None,
    },
    'ecdsa384': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQSgkOjkAvq7v5vHuj3KBL4/EAWcn5hZ
DyKcbyV0eBMGFq7hKXQlZqIahLVqeMR0QqmkxNJ2rly2VHcXneq3vZ+9fIsWCOdYk5WP3N
ZPzv911Xn7wbEkC7QndD5zKlm4pBUAAADomhj+IZoY/iEAAAATZWNkc2Etc2hhMi1uaXN0
cDM4NAAAAAhuaXN0cDM4NAAAAGEEoJDo5AL6u7+bx7o9ygS+PxAFnJ+YWQ8inG8ldHgTBh
au4Sl0JWaiGoS1anjEdEKppMTSdq5ctlR3F53qt72fvXyLFgjnWJOVj9zWT87/ddV5+8Gx
JAu0J3Q+cypZuKQVAAAAMQD5sTy8p+B1cn/DhOmXquui1BcxvASqzzevkBlbQoBa73y04B
2OdqVOVRkwZWRROz0AAAAbdGVzdCBrZXkgd2l0aG91dCBwYXNzcGhyYXNlAQIDBA==
-----END OPENSSH PRIVATE KEY-----
""",
        'private_key_blob': bytes.fromhex("""
            00 00 00 13 65 63 64
            73 61 2d 73 68 61 32 2d 6e 69 73 74 70 33 38 34
            00 00 00 08 6e 69 73 74 70 33 38 34
            00 00 00 61 04
            a0 90 e8 e4 02 fa bb bf 9b c7 ba 3d ca 04 be 3f
            10 05 9c 9f 98 59 0f 22 9c 6f 25 74 78 13 06 16
            ae e1 29 74 25 66 a2 1a 84 b5 6a 78 c4 74 42 a9
            a4 c4 d2 76 ae 5c b6 54 77 17 9d ea b7 bd 9f bd
            7c 8b 16 08 e7 58 93 95 8f dc d6 4f ce ff 75 d5
            79 fb c1 b1 24 0b b4 27 74 3e 73 2a 59 b8 a4 15
            00 00 00 31 00
            f9 b1 3c bc a7 e0 75 72 7f c3 84 e9 97 aa eb a2
            d4 17 31 bc 04 aa cf 37 af 90 19 5b 42 80 5a ef
            7c b4 e0 1d 8e 76 a5 4e 55 19 30 65 64 51 3b 3d
            00 00 00 1b 74 65 73 74 20 6b 65 79 20 77 69
            74 68 6f 75 74 20 70 61 73 73 70 68 72 61 73 65
"""),
        'public_key': rb"""ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBKCQ6OQC+ru/m8e6PcoEvj8QBZyfmFkPIpxvJXR4EwYWruEpdCVmohqEtWp4xHRCqaTE0nauXLZUdxed6re9n718ixYI51iTlY/c1k/O/3XVefvBsSQLtCd0PnMqWbikFQ== test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 13 65 63 64
            73 61 2d 73 68 61 32 2d 6e 69 73 74 70 33 38 34
            00 00 00 08 6e 69 73 74 70 33 38 34
            00 00 00 61 04
            a0 90 e8 e4 02 fa bb bf 9b c7 ba 3d ca 04 be 3f
            10 05 9c 9f 98 59 0f 22 9c 6f 25 74 78 13 06 16
            ae e1 29 74 25 66 a2 1a 84 b5 6a 78 c4 74 42 a9
            a4 c4 d2 76 ae 5c b6 54 77 17 9d ea b7 bd 9f bd
            7c 8b 16 08 e7 58 93 95 8f dc d6 4f ce ff 75 d5
            79 fb c1 b1 24 0b b4 27 74 3e 73 2a 59 b8 a4 15
"""),
        'expected_signature': None,
        'derived_passphrase': None,
    },
    'ecdsa521': {
        'private_key': rb"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQASVOdwDznmlcGqiLvFtYeVtrAEiVz
iIfsL7jEM8Utu/m8WSkPFQtjwqdFw+WfZ0mi6qMbEFgi/ELzZSKVteCSbcMAhqAkOMFKiD
u4bxvsM6bT02Ru7q2yT41ySyGhUD0QySBnI6Ckt/wnQ1TEpj8zDKiRErxs9e6QLGElNRkz
LPMs+mMAAAEY2FXeh9hV3ocAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
AAAIUEAElTncA855pXBqoi7xbWHlbawBIlc4iH7C+4xDPFLbv5vFkpDxULY8KnRcPln2dJ
ouqjGxBYIvxC82UilbXgkm3DAIagJDjBSog7uG8b7DOm09Nkbu6tsk+NckshoVA9EMkgZy
OgpLf8J0NUxKY/MwyokRK8bPXukCxhJTUZMyzzLPpjAAAAQSFqUmKK7lGQzxT6GKZSLDju
U3otwLYnuj+/5AdzuB/zotu95UdFv9I2DNXzd9E4WAyz6IqBBNcsMkxrzHAdqsYDAAAAG3
Rlc3Qga2V5IHdpdGhvdXQgcGFzc3BocmFzZQ==
-----END OPENSSH PRIVATE KEY-----
""",
        'private_key_blob': bytes.fromhex("""
            00 00 00 13 65 63 64
            73 61 2d 73 68 61 32 2d 6e 69 73 74 70 35 32 31
            00 00 00 08 6e 69 73 74 70 35 32 31
            00 00 00 85 04 00 49 53 9d
            c0 3c e7 9a 57 06 aa 22 ef 16 d6 1e 56 da c0 12
            25 73 88 87 ec 2f b8 c4 33 c5 2d bb f9 bc 59 29
            0f 15 0b 63 c2 a7 45 c3 e5 9f 67 49 a2 ea a3 1b
            10 58 22 fc 42 f3 65 22 95 b5 e0 92 6d c3 00 86
            a0 24 38 c1 4a 88 3b b8 6f 1b ec 33 a6 d3 d3 64
            6e ee ad b2 4f 8d 72 4b 21 a1 50 3d 10 c9 20 67
            23 a0 a4 b7 fc 27 43 54 c4 a6 3f 33 0c a8 91 12
            bc 6c f5 ee 90 2c 61 25 35 19 33 2c f3 2c fa 63
            00 00 00 41 21
            6a 52 62 8a ee 51 90 cf 14 fa 18 a6 52 2c 38 ee
            53 7a 2d c0 b6 27 ba 3f bf e4 07 73 b8 1f f3 a2
            db bd e5 47 45 bf d2 36 0c d5 f3 77 d1 38 58 0c
            b3 e8 8a 81 04 d7 2c 32 4c 6b cc 70 1d aa c6 03
            00 00 00 1b 74 65 73 74 20 6b 65 79 20 77 69
            74 68 6f 75 74 20 70 61 73 73 70 68 72 61 73 65
"""),
        'public_key': rb"""ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBABJU53APOeaVwaqIu8W1h5W2sASJXOIh+wvuMQzxS27+bxZKQ8VC2PCp0XD5Z9nSaLqoxsQWCL8QvNlIpW14JJtwwCGoCQ4wUqIO7hvG+wzptPTZG7urbJPjXJLIaFQPRDJIGcjoKS3/CdDVMSmPzMMqJESvGz17pAsYSU1GTMs8yz6Yw== test key without passphrase
""",  # noqa: E501
        'public_key_data': bytes.fromhex("""
            00 00 00 13 65 63 64
            73 61 2d 73 68 61 32 2d 6e 69 73 74 70 32 35 36
            00 00 00 08 6e 69 73 74 70 35 32 31
            00 00 00 85 04 00 49 53 9d
            c0 3c e7 9a 57 06 aa 22 ef 16 d6 1e 56 da c0 12
            25 73 88 87 ec 2f b8 c4 33 c5 2d bb f9 bc 59 29
            0f 15 0b 63 c2 a7 45 c3 e5 9f 67 49 a2 ea a3 1b
            10 58 22 fc 42 f3 65 22 95 b5 e0 92 6d c3 00 86
            a0 24 38 c1 4a 88 3b b8 6f 1b ec 33 a6 d3 d3 64
            6e ee ad b2 4f 8d 72 4b 21 a1 50 3d 10 c9 20 67
            23 a0 a4 b7 fc 27 43 54 c4 a6 3f 33 0c a8 91 12
            bc 6c f5 ee 90 2c 61 25 35 19 33 2c f3 2c fa 63
"""),
        'expected_signature': None,
        'derived_passphrase': None,
    },
}

DUMMY_SERVICE = 'service1'
DUMMY_PASSPHRASE = 'my secret passphrase'
DUMMY_KEY1 = SUPPORTED_KEYS['ed25519']['public_key_data']
DUMMY_KEY1_B64 = base64.standard_b64encode(DUMMY_KEY1).decode('ASCII')
DUMMY_KEY2 = SUPPORTED_KEYS['rsa']['public_key_data']
DUMMY_KEY2_B64 = base64.standard_b64encode(DUMMY_KEY2).decode('ASCII')
DUMMY_KEY3 = SUPPORTED_KEYS['ed448']['public_key_data']
DUMMY_KEY3_B64 = base64.standard_b64encode(DUMMY_KEY3).decode('ASCII')
DUMMY_CONFIG_SETTINGS = {
    'length': 10,
    'upper': 1,
    'lower': 1,
    'repeat': 5,
    'number': 1,
    'space': 1,
    'dash': 1,
    'symbol': 1,
}
DUMMY_RESULT_PASSPHRASE = b'.2V_QJkd o'
DUMMY_RESULT_KEY1 = b'E<b<{ -7iG'
DUMMY_PHRASE_FROM_KEY1_RAW = (
    b'\x00\x00\x00\x0bssh-ed25519'
    b'\x00\x00\x00@\xf0\x98\x19\x80l\x1a\x97\xd5&\x03n'
    b'\xcc\xe3e\x8f\x86f\x07\x13\x19\x13\t!33\xf9\xe46S'
    b'\x1d\xaf\xfd\r\x08\x1f\xec\xf8s\x9b\x8c_U9\x16|ST,'
    b'\x1eR\xbb0\xed\x7f\x89\xe2/iQU\xd8\x9e\xa6\x02'
)
DUMMY_PHRASE_FROM_KEY1 = b'8JgZgGwal9UmA27M42WPhmYHExkTCSEzM/nkNlMdr/0NCB/s+HObjF9VORZ8U1QsHlK7MO1/ieIvaVFV2J6mAg=='  # noqa: E501

VAULT_MASTER_KEY = 'vault key'
VAULT_V02_CONFIG = 'P7xeh5y4jmjpJ2pFq4KUcTVoaE9ZOEkwWmpVTURSSWQxbGt6emN4aFE4eFM3anVPbDRNTGpOLzY3eDF5aE1YTm5LNWh5Q1BwWTMwM3M5S083MWRWRFlmOXNqSFJNcStGMWFOS3c2emhiOUNNenZYTmNNMnZxaUErdlRoOGF2ZHdGT1ZLNTNLOVJQcU9jWmJrR3g5N09VcVBRZ0ZnSFNUQy9HdFVWWnFteVhRVkY3MHNBdnF2ZWFEbFBseWRGelE1c3BFTnVUckRQdWJSL29wNjFxd2Y2ZVpob3VyVzRod3FKTElTenJ1WTZacTJFOFBtK3BnVzh0QWVxcWtyWFdXOXYyenNQeFNZbWt1MDU2Vm1kVGtISWIxWTBpcWRFbyswUVJudVVhZkVlNVpGWDA4WUQ2Q2JTWW81SnlhQ2Zxa3cxNmZoQjJES0Uyd29rNXpSck5iWVBrVmEwOXFya1NpMi9saU5LL3F0M3N3MjZKekNCem9ER2svWkZ0SUJLdmlHRno0VlQzQ3pqZTBWcTM3YmRiNmJjTkhqUHZoQ0NxMW1ldW1XOFVVK3pQMEtUMkRMVGNvNHFlOG40ck5KcGhsYXg1b1VzZ1NYU1B2T3RXdEkwYzg4NWE3YWUzOWI1MDI0MThhMWZjODQ3MDA2OTJmNDQ0MDkxNGFiNmRlMGQ2YjZiNjI5NGMwN2IwMmI4MGZi'  # noqa: E501
VAULT_V02_CONFIG_DATA = {
    'global': {
        'phrase': DUMMY_PASSPHRASE.rstrip('\n'),
    },
    'services': {
        '(meta)': {
            'notes': 'This config was originally in v0.2 format.',
        },
        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
    },
}
VAULT_V03_CONFIG = 'sBPBrr8BFHPxSJkV/A53zk9zwDQHFxLe6UIusCVvzFQre103pcj5xxmE11lMTA0U2QTYjkhRXKkH5WegSmYpAnzReuRsYZlWWp6N4kkubf+twZ9C3EeggPm7as2Af4TICHVbX4uXpIHeQJf9y1OtqrO+SRBrgPBzgItoxsIxebxVKgyvh1CZQOSkn7BIzt9xKhDng3ubS4hQ91fB0QCumlldTbUl8tj4Xs5JbvsSlUMxRlVzZ0OgAOrSsoWELXmsp6zXFa9K6wIuZa4wQuMLQFHiA64JO1CR3I+rviWCeMlbTOuJNx6vMB5zotKJqA2hIUpN467TQ9vI4g/QTo40m5LT2EQKbIdTvBQAzcV4lOcpr5Lqt4LHED5mKvm/4YfpuuT3I3XCdWfdG5SB7ciiB4Go+xQdddy3zZMiwm1fEwIB8XjFf2cxoJdccLQ2yxf+9diedBP04EsMHrvxKDhQ7/vHl7xF2MMFTDKl3WFd23vvcjpR1JgNAKYprG/e1p/7'  # noqa: E501
VAULT_V03_CONFIG_DATA = {
    'global': {
        'phrase': DUMMY_PASSPHRASE.rstrip('\n'),
    },
    'services': {
        '(meta)': {
            'notes': 'This config was originally in v0.3 format.',
        },
        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
    },
}
VAULT_STOREROOM_CONFIG_ZIPPED = b"""
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
"""
VAULT_STOREROOM_CONFIG_DATA = {
    'global': {
        'phrase': DUMMY_PASSPHRASE.rstrip('\n'),
    },
    'services': {
        '(meta)': {
            'notes': 'This config was originally in storeroom format.',
        },
        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
    },
}

_VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED_JAVASCRIPT_SOURCE = """
// Executed in the top-level directory of the vault project code, in Node.js.
const storeroom = require('storeroom')
const Store = require('./lib/store.js')
let store = new Store(storeroom.createFileAdapter('./broken-dir'), 'vault key')
await store._storeroom.put('/services/array/', ['entry1','entry2'])
// The resulting "broken-dir" was then zipped manually.
"""
VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED = b"""
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
"""

_VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED2_JAVASCRIPT_SOURCE = """
// Executed in the top-level directory of the vault project code, in Node.js.
const storeroom = require('storeroom')
const Store = require('./lib/store.js')
let store = new Store(storeroom.createFileAdapter('./broken-dir'), 'vault key')
await store._storeroom.put('/services/array/', 'not a directory index')
// The resulting "broken-dir" was then zipped manually.
"""
VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED2 = b"""
UEsDBAoAAAAAAM6NSVmrcHdV5gAAAOYAAAAFAAAALmtleXN7InZlcnNpb24iOjF9CkV3ZS9LZkJp
L0V0OUcrZmxYM3gxaFU4ZjE4YlE3S253bHoxN0IxSDE3cUhVOGdWK2RpWWY5MTdFZ0YrSStidEpZ
VXBzWVZVck45OC9uLzdsZnl2NUdGVEg2NWZxVy93YjlOc2MxeEZ4ck43Q3p4eTZ5MVAxZzFPb2VK
b0RZU3J6YXlwT0E2M3pidmk0ZTRiREMyNXhPTXl5NHBoMDFGeGdnQmpSNnpUcmR2UDk2UlZQd0I5
WitOZkZWZUlXT1NQN254ZFNYMGdFbkZ4SDBmWDkzNTFaTTZnPVBLAwQKAAAAAADOjUlZJg3/BhcC
AAAXAgAAAgAAADBieyJ2ZXJzaW9uIjoxfQpBVXJJMjNDQ2VpcW14cUZRMlV4SUpBaUoxNEtyUzh2
SXpIa2xROURBaFRlVHNFMmxPVUg4WUhTcUk1cXRGSHBqY3c1WkRkZmRtUlEwQXVGRjllY3lkam14
dDdUemRYLzNmNFUvTGlVV2dLRmQ1K1FEN3BlVlE1bWpqeHNlUEpHTDlhTWlKaGxSUVB4SmtUbjBx
U2poM1RUT0ZZbVAzV0JkdlUyWnF2RzhaSDk2cU1WcnZsQ0dMRmZTc2svVXlvcHZKdENONUVXcTRZ
SDUwNFNiejFIUVhWd2RjejlrS1BuR3J6SVA4ZmZtZnhXQ0U0TmtLb0ZPQXZuNkZvS3FZdGlGbFE9
PQpBVXBMUVMrMG9VeEZTeCtxbTB3SUtyM1MvTVJxYWJJTFlEUnY0aHlBMVE2TGR2Nlk0UmJ0enVz
NzRBc0cxbVhhenlRU2hlZVowdk0xM2ZyTFA4YlV0VHBaRyszNXF1eUhLM2NaWVJRZUxKM0JzejZz
b0xaQjNZTkpNenFxTTQrdzM1U0FZZ2lMU1NkN05NeWVrTHNhRUIzRDFOajlTRk85K3NGNEpFMWVL
UXpNMkltNk9qOUNVQjZUSTV3UitibksxN1BnY2RaeTZUMVRMWElVREVxcDg4dWdsWmRFTVcrNU9k
aE5ZbXEzZERWVWV4UnJpM1AwUmVBSi9KMGdJNkNoUUE9PVBLAwQKAAAAAADOjUlZTNfdphcCAAAX
AgAAAgAAADBmeyJ2ZXJzaW9uIjoxfQpBWVJqOVpIUktGUEVKOHM2YVY2TkRoTk5jQlZ5cGVYUmdz
cnBldFQ0cGhJRGROWFdGYzRia0daYkJxMngwRDFkcVNjYWk5UzEveDZ2K28zRE0rVEF2OVE3ZFVR
QWVKR3RmRkhJZDZxWW0ybEdNSnF5WTRNWm14aE9YdXliend0V3Q4Mnhvb041QTZNcWpINmxKQllD
UUN3ZEJjb3RER0EwRnlnVTEzeHV2WnIzT1puZnFFRGRqbzMxNkw5aExDN1RxMTYwUHpBOXJOSDMz
ZkNBcUhIVXZiYlFQQWErekw1d3dEN3FlWkY2MHdJaEwvRmk5L3JhNGJDcHZRNC9ORWpRd3c9PQpB
WWNGUDB1Y2xMMHh3ZDM2UXZXbm4wWXFsOU5WV0s3c05CMTdjdmM3N3VDZ0J2OE9XYkR5UHk5d05h
R2NQQzdzcVdZdHpZRlBHR0taVjhVUzA1YTVsV1BabDNGVFNuQXNtekxPelBlcFZxaitleDU3aEsx
QnV1bHkrUCtYQkE0YUtsaDM3c0RJL3I0UE1BVlJuMDNoSDJ5dEhDMW9PbjF0V1M5Q1NLV1pSMThh
djdTT0RBMVBNRnFYTmZKZVNTaVJiQ2htbDdOcFVLbjlXSGJZandybDlqN0JSdy9kWjhNQldCb3Ns
Nlc1dGZtdnJMVHhGRFBXYUgzSUp0T0czMEI1M3c9PVBLAwQKAAAAAADOjUlZn9rNID8CAAA/AgAA
AgAAADFkeyJ2ZXJzaW9uIjoxfQpBYWFBb3lqaGljVDZ4eXh1c0U0RVlDZCtxbE81Z0dEYTBNSFVS
MmgrSW9QMHV4UkY3b1BRS2czOHlQUEN3Ny9MYVJLQ0dQZ0RyZ2RpTWJTeUwzZ3ZNMFhseVpVMVBW
QVJvNEFETU9lbXgrOWhtS0hjQWNKMG5EeW5oSkhGYTYyb2xyQUNxekZzblhKNVBSeEVTVzVEbUh0
Ui9nRm5Wa1FvalhyVW4ybmpYMjVVanZQaXhlMU96Y0daMmQ0MjdVTGdnY1hqMkhSdjJiZldDNDUw
SGFXS3FDckZlYWlrQ2xkUUM2WGV3SkxZUjdvQUY3UjVha2ttK3M2MXNCRTVCaTg0QmJLWHluc1NG
ejE0TXFrd2JMK1VMYVk9CkFUT3dqTUFpa3Q4My9NTW5KRXQ2b3EyNFN4KzJKNDc2K2gyTmEzbHUr
MDg0cjlBT25aaUk0TmlYV0N1Q0lzakEzcTBwUHFJS1VXZHlPQW9uM2VHY0huZUppWUtVYllBaUJI
MVNmbnhQQkMzZkFMRklybkQ4Y0VqeGpPcUFUaTQ5dE1mRmtib0dNQ3dEdFY0V3NJL0tLUlRCOFd1
MnNXK2J0V3QzVWlvZG9ZeUVLTDk3ekNNemZqdGptejF4SDhHTXY5WDVnaG9NSW5RQVNvYlRreVZ4
dWo5YnlDazdNbU0vK21ZL3AwZE9oYVY0Nncwcm04UGlvWEtzdzR4bXB3ditDWC9PRXV3Uy9meDJT
Y0lOQnNuYVRiWT1QSwECHgMKAAAAAADOjUlZq3B3VeYAAADmAAAABQAAAAAAAAAAAAAApIEAAAAA
LmtleXNQSwECHgMKAAAAAADOjUlZJg3/BhcCAAAXAgAAAgAAAAAAAAAAAAAApIEJAQAAMGJQSwEC
HgMKAAAAAADOjUlZTNfdphcCAAAXAgAAAgAAAAAAAAAAAAAApIFAAwAAMGZQSwECHgMKAAAAAADO
jUlZn9rNID8CAAA/AgAAAgAAAAAAAAAAAAAApIF3BQAAMWRQSwUGAAAAAAQABADDAAAA1gcAAAAA
"""

_VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED3_JAVASCRIPT_SOURCE = """
// Executed in the top-level directory of the vault project code, in Node.js.
const storeroom = require('storeroom')
const Store = require('./lib/store.js')
let store = new Store(storeroom.createFileAdapter('./broken-dir'), 'vault key')
await store._storeroom.put('/services/array/', [null, 1, true, [], {}])
// The resulting "broken-dir" was then zipped manually.
"""
VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED3 = b"""
UEsDBAoAAAAAAEOPSVnVlcff5gAAAOYAAAAFAAAALmtleXN7InZlcnNpb24iOjF9CkV4dVBHUDBi
YkxrUVdvWnV5ZUJQRy8xdmM2MCt6MThOa3BsS09ydFAvUTVnQmxkYVpIOG10dTE5VWZFNGdGRGRj
eHJtWUd4eXZDZFNqcVlOaDh4cTlzM3VydkdRTWFwcnhtdlZGZUxoSW4zZnVlTDAweEk0ZmlLenZN
MmthUlRsNWNORGh3eUNlWVk4dzhBcXNhYjNyVWVsOEE0eVQ0cHU2d2tmQ3dTWUdqeG5HR29EcWJK
VnVJVWNpZVBEcU9PTzU2b0MyMG9lT01adFVkTUtxV28zYnFZPVBLAwQKAAAAAABDj0lZ77OVHxcC
AAAXAgAAAgAAADBjeyJ2ZXJzaW9uIjoxfQpBZllFQVVobEkyU2lZeGlrdWh0RzRNbUN3L1V2THBN
VVhwVlB0NlRwdzRyNGdocVJhbGZWZ0hxUHFtbTczSnltdFFrNnZnR2JRdUpiQmVlYjYwOHNrMGk4
ZFJVZjNwdlc2SnUyejljQkdwOG5mTFpTdlNad1lLN09UK2gzSDNDcmoxbXNicEZUcHVldW81NXc1
dGdYMnBuWXNWTVcrczdjaHEyMUIya2lIVEZrdGt1MXlaRzhPYkVUQjNCOFNGODVVbi9CUjFEMHJ1
ME9zOWl4ZWM2VmNTMitTZndtNnNtSlk2ZW9ZNTJzOGJNRGdYMndjQ0srREdkOEo2VWp0NG5OQVE9
PQpBUWlPRnRZcmJybWUycEwxRFpGT1BjU0RHOUN2cVkvbHhTWGIwaVJUdmtIWFc2bEtHL0p4RUtU
d3RTc0RTeDhsMTUvaHRmbWpOQ2tuTzhLVEFoKzhRQm5FbjZ0a2x5Y3BmeEIrTUxLRjFCM1Q1bjcv
T0VUMExMdmgxU2k1bnRRNXhTUHZZNWtXeUMyZjhXUXFZb3FSNU5JVENMeDV6dWNsQ3dGb2kvVXc4
OWNNWjM1MHBSbThzUktJbjJFeDUrQ1JwS3ZHdnBHbFJaTmk5VHZmVkNic1FCalR3MC9aeklTdzVQ
NW9BVWE2U1ExUVFnNHg4VUNkY0s2QUNLaFluY0d4TVE9PVBLAwQKAAAAAABDj0lZGk9LVj8CAAA/
AgAAAgAAADE0eyJ2ZXJzaW9uIjoxfQpBY1g2NVpMUWk4ck9pUlIyWGEwQlFHQVhQVWF2aHNJVGVY
c2dzRk9OUmFTRzJCQlg0SGxJRHpwRUd5aDUrZ2czZVRwWDFNOERua3pMeTVzcWRkMFpmK3padTgz
Qm52Y1JPREVIVDllUW91YUtPTWltdlRYanNuSXAxUHo5VGY1TlRkRjNJVTd2V1lhUDg4WTI5NG1i
c1VVL2RKVTZqZ3ZDbUw2cE1VZ28xUU12bGJnaVp3cDV1RDFQZXlrSXdKVWdJSEgxTEpnYi9xU2tW
c25leW1XY1RXR0NobzRvZGx3S2hJWmFCelhvNFhlN2U1V2I2VHA3Rkk5VUpVcmZIRTAvcVdrZUZE
VmxlazY3cUx3ZFZXcU9DdFk9CkFhSGR0QjhydmQ0U3N4ZmJ5eU1OOHIzZEoxeHA5NmFIRTQvalNi
Z05hZWttaDkyb2ROM1F4MUlqYXZsYVkxeEt1eFF3KzlwTHFIcTF5a1JSRjQzL2RVWGFIRk5UU0NX
OVFsdmd3KzMwa1ZhSEdXRllvbFRnRWE4djQ3b3VrbGlmc01PZGM0YVNKb2R4ZUFJcVc3Q1cwdDVR
b2RUbWREUXpqc3phZkQ4R2VOd2NFQjdGMHI2RzNoZEJlQndxd3Z6eENVYnpSUmU5bEQ3NjQ3RFp1
bEo1U3c4amlvV0paTW40NlZhV3BYUXk4UnNva3hHaW00WUpybUZIQ2JkVU9qSWJsUmQ1Z3VhUDNU
M0NxeHRPdC94b1BhOD1QSwMECgAAAAAAQ49JWVJM8QYXAgAAFwIAAAIAAAAxNnsidmVyc2lvbiI6
MX0KQVlCWDF6M21qUlQrand4M2FyNkFpemxnalJZbUM0ZHg5NkxVQVBTVHNMWXJKVHFtWnd5N0Jy
OFlCcElVamorMHdlT3lNaUtLVnFwaER3RXExNWFqUmlSZUVEQURTVHZwWmlLZUlnZjR5elUzZXNP
eDJ2U2J1bXhTK0swUGZVa2tsSy9TRmRiU3EvUHFMRjBDRTVCMXNyKzJLYTB2WlJmak94R3VFeFRD
RXozN0ZlWDNNR3NCNkhZVHEzaUJWcUR6NVB6eHpCWWM5Kyt6RitLS1RnMVp2NGRtRmVQTC9JSEY5
WnV6TWlqRXdCRkE3WnJ0dkRqd3ZYcWtsMVpsR0c4eUV3PT0KQVhUWkRLVnNleldpR1RMUVZqa2hX
bXBnK05MYlM0M2MxZEpvK2xGcC9yWUJYZkw3Wll5cGdjWE5IWXNzd01nc2VSSTAzNmt6bGZkdGNa
bTdiUUN6M2JuQmZ6ZlorZFFuT2Y5STVSU2l0QzB2UmsydkQrOFdwbmRPSzNucGY5S0VpWklOSzVq
TEZGTTJDTkNmQzBabXNRUlF3T0k2N3l5ZHhjVnFDMXBnWHV6QXRXamlsSUpnN0p6eUtsY3BJUGJu
SUc0UzRSUlhIdW1wZnpoeWFZWkd6T0FDamRSYTZIMWJxYkJkZXFaSHMvQXJvM25mVjdlbjhxSUE5
aVUrbnNweXFnPT1QSwECHgMKAAAAAABDj0lZ1ZXH3+YAAADmAAAABQAAAAAAAAAAAAAApIEAAAAA
LmtleXNQSwECHgMKAAAAAABDj0lZ77OVHxcCAAAXAgAAAgAAAAAAAAAAAAAApIEJAQAAMGNQSwEC
HgMKAAAAAABDj0lZGk9LVj8CAAA/AgAAAgAAAAAAAAAAAAAApIFAAwAAMTRQSwECHgMKAAAAAABD
j0lZUkzxBhcCAAAXAgAAAgAAAAAAAAAAAAAApIGfBQAAMTZQSwUGAAAAAAQABADDAAAA1gcAAAAA
"""

_VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED4_JAVASCRIPT_SOURCE = """
// Executed in the top-level directory of the vault project code, in Node.js.
const storeroom = require('storeroom')
const Store = require('./lib/store.js')
let store = new Store(storeroom.createFileAdapter('./broken-dir'), 'vault key')
await store._storeroom.put('/dir/subdir/', [])
await store._storeroom.put('/dir/', [])
// The resulting "broken-dir" was then zipped manually.
"""
VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED4 = b"""
UEsDBAoAAAAAAE+5SVloORS+5gAAAOYAAAAFAAAALmtleXN7InZlcnNpb24iOjF9CkV6dWRoNkRQ
YTlNSWFabHZ5TytVYTFuamhjV2hIaTFBU0lKYW5zcXBxVlA0blN2V0twUzdZOUc2bjFSbi8vUnVM
VitwcHp5SC9RQk83R0hFenNVMzdCUzFwUmVVeGhxUVlVTE56OXZvQ0crM1ZaL3VncU44dDJiU05m
Nyt5K3hiNng2aVlFUmNZYTJ0UkhzZVdIc0laTE9ha2lDb0lRVGV3cndwYjVMM2pnd0E3SXBzaDkz
QkxHSzM5dXNYNmo0R0I2WkRUeW5JcGk4V3JkbDhnWVZCN0tVPVBLAwQKAAAAAABPuUlZ663uUhcC
AAAXAgAAAgAAADAzeyJ2ZXJzaW9uIjoxfQpBV2wzS2gzd21ZSFVZZU1RR3BLSVowdVd1VXFna09h
YmRjNzNYYXVsZTNtVS9sN2Zvd1AyS21jbFp3ZDM5V3lYVzRTcEw4R0l4YStDZW51S3V0Wm5nb0FR
bWlnaUJUbkFaais5TENCcGNIWlZNY2RBVkgxKzBFNGpsanZ1UkVwZ0tPS05LZjRsTUl1QnZ4VmFB
ZkdwNHJYNEZ4MmpPSlk1Y3NQZzBBRFBoZVAwN29GWVQ3alorSUNEK1AxNGZPdWpwMGRUeDRrTDIy
LzlqalRDNXBCNVF5NW5iOUx3Zk5DUWViSUVpaTZpbU0vRmFrK1dtV05tMndqMERSTEc4RHY3ZkE9
PQpBU0c3NTNGTVVwWmxjK3E1YXRzcC93OUNqN2JPOFlpY24wZHg2UGloTmwzUS9WSjVVeGJmU3l0
ZDFDNDBRU2xXeTJqOTJDWUd3VER6eEdBMXVnb0FCYi9kTllTelVwbHJFb3BuUVphYXdsdTVwV2x0
Y1E5WTcveWN4S2E4b0JaaGY3RkFYcGo2c01wUW9zNzI5VFVabFd4UmI4VFRtN2FrVnR1OXcvYXlK
RS9reDh4ZUYxSGJlc3Q4N1IxTGg2ODd3dS9XVUN2ZjNXYXo1VjNnZWY0RnpUTXg0bkpqSlZOd0U0
SzAxUTlaVzQ0bmVvbExPUVI1MkZDeDZvbml3RW9tenc9PVBLAwQKAAAAAABPuUlZRXky4CsCAAAr
AgAAAgAAADEweyJ2ZXJzaW9uIjoxfQpBWmlYWVlvNUdCY2d5dkFRaGtyK2ZjUkdVSkdabDd2dE5w
T2Mrd1VzbXJhQWhRN3dKdlYraGhKcTlrcWNKQnBWU0gyUTBTTVVhb29iNjBJM1NYNUNtTkJRU2FH
M3prd0Y0T2F4TnpCZUh0NFlpaDd4Y3p2ak4xR0hISDJQYW0xam05K09ja3JLVmNMVURtNXRKb2ZC
Z1E4Q2NwMGZMVkdEaURjNWF0MjVMc2piQVcvNkZFSnJ5VVBHWis4UVdYRmlWMGdtVVZybVc3VUFy
dGhJQitWNTdZS1BORi95Nng2OU43UTFQbmp1cUczdlpybzljMEJ3d012NWoyc3BMMTJHcTdzTDZE
alB1d0dHbnB2MkVZQTFLbmc9CkFTdjQwUkgzRmxzbGVlU1NjRlZNRmh3dEx6eEYxK2xpcmxEL29X
alJLQ05qVWZhUVpJTWpqMWRoVkhOakNUTWhWZ1ZONkl3b04xTnFOMEV6cmdhaTFBWnNiMm9UczYw
QkI1UGh0U0hhQ2U2WllUeE1JemFPS2FIK0w2eHhtaXIrTlQxNTRXS0x5amJMams3MU1na3Nwa0Yy
WDBJMnlaWW5IUUM0bmdEL24yZzRtSVI2Q1hWL0JOUXNzeTBEeXdGLzN6eGRRYWw5cFBtVk1qYnFu
cHY5SFNqRTg4S25naVpBWFhJWU1OVGF2L3Q3Y3dEWGdNekhKTlU0Y2xnVUtIQVZ3QT09UEsDBAoA
AAAAAE+5SVkPfKx9FwIAABcCAAACAAAAMWR7InZlcnNpb24iOjF9CkFYbHNLRzQwZG5ibTJvcXdY
U2ZrSWp3Mmxpa0lDS3hVOXU3TU52VkZ1NEJ2R1FVVitSVVdsS3MxL25TSlBtM2U2OTRvVHdoeDFo
RFF3U0M5U0QvbXd5bnpjSTloUnRCUWVXMkVMOVU5L1ZGcHFsVWY3Z1ZOMHZ0ZWpXYnV4QnhsZlRD
Tys4SFBwU2Zaa2VOUld5R2JNdzBFSU9LTmxRYjk3OUF0c1g3THR0NytaTkJnakZHYkZxaHdwa3kx
WUNDVng1UmNZZ2tma2ZjWnVncGpzc1RzNVFvK1p3QXBEcDZ4V3JjSHMxUDhvNktBRzAwcjZZbkNM
N2ErU1dwZmVNTUJhZz09CkFadVF0cFZMWmVvb292NkdyQlpnb3B6VmRGUXBlK1h6QXZuZ2dPVnZM
VWtCYVF2akl5K1VLdXVUVlFoQ1JiMVp6dGZQL2dsNnoxOEsyZW5sQlo2bGJTZnoxTlBWeUVzYXB3
dDVpUVh4azd5UkJlZks1cFlsNTduUXlmcFZQbzlreFpnOVdHTkV3NVJ5MkExemhnNGl6TWxLRmJh
UjZFZ0FjQ3NFOXAveGRLa29ZNjhOUlZmNXJDM3lMQjc3ZWgyS1hCUld2WDNZcE9XdW00OGtsbmtI
akJjMFpiQmUrT3NZb3d5cXpoRFA2ZGQxRlFnMlFjK09vc3B4V0sycld4M01HZz09UEsBAh4DCgAA
AAAAT7lJWWg5FL7mAAAA5gAAAAUAAAAAAAAAAAAAAKSBAAAAAC5rZXlzUEsBAh4DCgAAAAAAT7lJ
Weut7lIXAgAAFwIAAAIAAAAAAAAAAAAAAKSBCQEAADAzUEsBAh4DCgAAAAAAT7lJWUV5MuArAgAA
KwIAAAIAAAAAAAAAAAAAAKSBQAMAADEwUEsBAh4DCgAAAAAAT7lJWQ98rH0XAgAAFwIAAAIAAAAA
AAAAAAAAAKSBiwUAADFkUEsFBgAAAAAEAAQAwwAAAMIHAAAAAA==
"""

CANNOT_LOAD_CRYPTOGRAPHY = (
    'Cannot load the required Python module "cryptography".'
)

skip_if_cryptography_support = pytest.mark.skipif(
    importlib.util.find_spec('cryptography') is not None,
    reason='cryptography support available; cannot test "no support" scenario',
)
skip_if_no_cryptography_support = pytest.mark.skipif(
    importlib.util.find_spec('cryptography') is None,
    reason='no "cryptography" support',
)

hypothesis_settings_coverage_compatible = (
    hypothesis.settings(
        # Running under coverage with the Python tracer increases
        # running times 40-fold, on my machines.  Sadly, not every
        # Python version offers the C tracer, so sometimes the Python
        # tracer is used anyway.
        deadline=(
            40 * deadline
            if (deadline := hypothesis.settings().deadline) is not None
            else None
        ),
        suppress_health_check=(hypothesis.HealthCheck.too_slow,),
    )
    if sys.gettrace() is not None
    else hypothesis.settings()
)


def list_keys(self: Any = None) -> list[_types.KeyCommentPair]:
    del self  # Unused.
    Pair = _types.KeyCommentPair  # noqa: N806
    list1 = [
        Pair(value['public_key_data'], f'{key} test key'.encode('ASCII'))
        for key, value in SUPPORTED_KEYS.items()
    ]
    list2 = [
        Pair(value['public_key_data'], f'{key} test key'.encode('ASCII'))
        for key, value in UNSUITABLE_KEYS.items()
    ]
    return list1 + list2


def sign(
    self: Any, key: bytes | bytearray, message: bytes | bytearray
) -> bytes:
    del self  # Unused.
    assert message == vault.Vault._UUID
    for value in SUPPORTED_KEYS.values():
        if value['public_key_data'] == key:  # pragma: no branch
            assert value['expected_signature'] is not None
            return value['expected_signature']
    raise AssertionError


def list_keys_singleton(self: Any = None) -> list[_types.KeyCommentPair]:
    del self  # Unused.
    Pair = _types.KeyCommentPair  # noqa: N806
    list1 = [
        Pair(value['public_key_data'], f'{key} test key'.encode('ASCII'))
        for key, value in SUPPORTED_KEYS.items()
    ]
    return list1[:1]


def suitable_ssh_keys(conn: Any) -> Iterator[_types.KeyCommentPair]:
    del conn  # Unused.
    Pair = _types.KeyCommentPair  # noqa: N806
    yield from [
        Pair(DUMMY_KEY1, b'no comment'),
        Pair(DUMMY_KEY2, b'a comment'),
    ]


def phrase_from_key(key: bytes) -> bytes:
    if key == DUMMY_KEY1:  # pragma: no branch
        return DUMMY_PHRASE_FROM_KEY1
    raise KeyError(key)  # pragma: no cover


@contextlib.contextmanager
def isolated_config(
    monkeypatch: pytest.MonkeyPatch,
    runner: click.testing.CliRunner,
) -> Iterator[None]:
    prog_name = cli.PROG_NAME
    env_name = prog_name.replace(' ', '_').upper() + '_PATH'
    with runner.isolated_filesystem():
        monkeypatch.setenv('HOME', os.getcwd())
        monkeypatch.setenv('USERPROFILE', os.getcwd())
        monkeypatch.delenv(env_name, raising=False)
        config_dir = cli._config_filename(subsystem=None)
        os.makedirs(config_dir, exist_ok=True)
        yield


@contextlib.contextmanager
def isolated_vault_config(
    monkeypatch: pytest.MonkeyPatch,
    runner: click.testing.CliRunner,
    config: Any,
) -> Iterator[None]:
    with isolated_config(monkeypatch=monkeypatch, runner=runner):
        config_filename = cli._config_filename(subsystem='vault')
        with open(config_filename, 'w', encoding='UTF-8') as outfile:
            json.dump(config, outfile)
        yield


@contextlib.contextmanager
def isolated_vault_exporter_config(
    monkeypatch: pytest.MonkeyPatch,
    runner: click.testing.CliRunner,
    vault_config: str | bytes | None = None,
    vault_key: str | None = None,
) -> Iterator[None]:
    if TYPE_CHECKING:
        chdir = contextlib.chdir
    else:
        try:
            chdir = contextlib.chdir
        except AttributeError:

            @contextlib.contextmanager
            def chdir(newpath: str) -> Iterator[None]:  # pragma: no branch
                oldpath = os.getcwd()
                os.chdir(newpath)
                yield
                os.chdir(oldpath)

    with runner.isolated_filesystem():
        monkeypatch.setenv('HOME', os.getcwd())
        monkeypatch.setenv('USERPROFILE', os.getcwd())
        monkeypatch.delenv('VAULT_PATH', raising=False)
        monkeypatch.delenv('VAULT_KEY', raising=False)
        monkeypatch.delenv('LOGNAME', raising=False)
        monkeypatch.delenv('USER', raising=False)
        monkeypatch.delenv('USERNAME', raising=False)
        if vault_key is not None:
            monkeypatch.setenv('VAULT_KEY', vault_key)
        # Use match/case here once Python 3.9 becomes unsupported.
        if isinstance(vault_config, str):
            with open('.vault', 'w', encoding='UTF-8') as outfile:
                print(vault_config, file=outfile)
        elif isinstance(vault_config, bytes):
            os.makedirs('.vault', mode=0o700, exist_ok=True)
            with (
                chdir('.vault'),
                tempfile.NamedTemporaryFile(suffix='.zip') as tmpzipfile,
            ):
                for line in vault_config.splitlines():
                    tmpzipfile.write(base64.standard_b64decode(line))
                tmpzipfile.flush()
                tmpzipfile.seek(0, 0)
                with zipfile.ZipFile(tmpzipfile.file) as zipfileobj:
                    zipfileobj.extractall()
        elif vault_config is None:
            pass
        else:  # pragma: no cover
            assert_never(vault_config)
        yield


def auto_prompt(*args: Any, **kwargs: Any) -> str:
    del args, kwargs  # Unused.
    return DUMMY_PASSPHRASE


def make_file_readonly(
    pathname: str | bytes | os.PathLike[str],
    /,
    *,
    try_race_free_implementation: bool = True,
) -> None:
    """Mark a file as read-only.

    On POSIX, this entails removing the write permission bits for user,
    group and other, and ensuring the read permission bit for user is
    set.

    Unfortunately, Windows has its own rules: Set exactly(?) the read
    permission bit for user to make the file read-only, and set
    exactly(?) the write permission bit for user to make the file
    read/write; all other permission bit settings are ignored.

    The cross-platform procedure therefore is:

    1. Call `os.stat` on the file, noting the permission bits.
    2. Calculate the new permission bits POSIX-style.
    3. Call `os.chmod` with permission bit `stat.S_IREAD`.
    4. Call `os.chmod` with the correct POSIX-style permissions.

    If the platform supports it, we use a file descriptor instead of
    a path name.  Otherwise, we use the same path name multiple times,
    and are susceptible to race conditions.

    """
    fname: int | str | bytes | os.PathLike[str]
    if try_race_free_implementation and {os.stat, os.chmod} <= os.supports_fd:
        fname = os.open(
            pathname,
            os.O_RDONLY
            | getattr(os, 'O_CLOEXEC', 0)
            | getattr(os, 'O_NOCTTY', 0),
        )
    else:
        fname = pathname
    try:
        orig_mode = os.stat(fname).st_mode
        new_mode = (
            orig_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH
            | stat.S_IREAD
        )
        os.chmod(fname, stat.S_IREAD)
        os.chmod(fname, new_mode)
    finally:
        if isinstance(fname, int):
            os.close(fname)


class ReadableResult(NamedTuple):
    """Helper class for formatting and testing click.testing.Result objects."""

    exception: BaseException | None
    exit_code: int
    output: str
    stderr: str

    @classmethod
    def parse(cls, r: click.testing.Result, /) -> Self:
        try:
            stderr = r.stderr
        except ValueError:
            stderr = r.output
        return cls(r.exception, r.exit_code, r.output or '', stderr or '')

    def clean_exit(
        self, *, output: str = '', empty_stderr: bool = False
    ) -> bool:
        """Return whether the invocation exited cleanly.

        Args:
            output:
                An expected output string.

        """
        return (
            (
                not self.exception
                or (
                    isinstance(self.exception, SystemExit)
                    and self.exit_code == 0
                )
            )
            and (not output or output in self.output)
            and (not empty_stderr or not self.stderr)
        )

    def error_exit(
        self, *, error: str | type[BaseException] = BaseException
    ) -> bool:
        """Return whether the invocation exited uncleanly.

        Args:
            error:
                An expected error message, or an expected numeric error
                code, or an expected exception type.

        """
        # Use match/case here once Python 3.9 becomes unsupported.
        if isinstance(error, str):
            return (
                isinstance(self.exception, SystemExit)
                and self.exit_code > 0
                and (not error or error in self.stderr)
            )
        else:  # noqa: RET505
            return isinstance(self.exception, error)


def parse_sh_export_line(line: str, *, env_name: str) -> str:
    line = line.rstrip('\r\n')
    shlex_parser = shlex.shlex(
        instream=line, posix=True, punctuation_chars=True
    )
    shlex_parser.whitespace = ' \t'
    tokens = list(shlex_parser)
    orig_tokens = tokens.copy()
    if tokens[-1] == ';':
        tokens.pop()
    if tokens[-3:] == [';', 'export', env_name]:
        tokens[-3:] = []
        tokens[:0] = ['export']
    if not (
        len(tokens) == 2
        and tokens[0] == 'export'
        and tokens[1].startswith(f'{env_name}=')
    ):
        msg = f'Cannot parse sh line: {orig_tokens!r} -> {tokens!r}'
        raise ValueError(msg)
    return tokens[1].split('=', 1)[1]
