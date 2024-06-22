# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

import click.testing
import derivepassphrase
import derivepassphrase.cli
import pytest

DUMMY_SERVICE = 'service1'
DUMMY_PASSPHRASE = b'my secret passphrase\n'

def test_200_help_output():
    runner = click.testing.CliRunner(mix_stderr=False)
    result = runner.invoke(derivepassphrase.cli.derivepassphrase, ['--help'])
    assert result.exit_code == 0
    assert 'Password generation:\n' in result.output, (
        'Option groups not respected in help text.'
    )
    assert 'Use NUMBER=0, e.g. "--symbol 0"' in result.output, (
        'Option group epilog not printed.'
    )

@pytest.mark.parametrize(['option'],
                         [('--lower',), ('--upper',), ('--number',),
                          ('--space',), ('--dash',), ('--symbol',),
                          ('--repeat',), ('--length',)])
def test_201_invalid_argument_range(option):
    runner = click.testing.CliRunner(mix_stderr=False)
    result = runner.invoke(derivepassphrase.cli.derivepassphrase,
                           [option, '-42', '-p', DUMMY_SERVICE],
                           input=DUMMY_PASSPHRASE)
    assert result.exit_code > 0, (
        f'program unexpectedly succeeded'
    )
    assert result.stderr_bytes, (
        f'program did not print any error message'
    )
    assert b'Error: Invalid value' in result.stderr_bytes, (
        f'program did not print the expected error message'
    )

@pytest.mark.parametrize(['charset_name'],
                         [('lower',), ('upper',), ('number',), ('space',),
                          ('dash',), ('symbol',)])
@pytest.mark.xfail(reason='implementation not written yet')
def test_202_disable_character_set(charset_name):
    option = f'--{charset_name}'
    charset = derivepassphrase.Vault._CHARSETS[charset_name].decode('ascii')
    runner = click.testing.CliRunner(mix_stderr=False)
    result = runner.invoke(derivepassphrase.cli.derivepassphrase,
                           [option, '0', '-p', DUMMY_SERVICE],
                           input=DUMMY_PASSPHRASE)
    assert result.exit_code == 0, (
        f'program died unexpectedly with exit code {result.exit_code}'
    )
    assert not result.stderr_bytes, (
        f'program barfed on stderr: {result.stderr_bytes}'
    )
    for c in charset:
        assert c not in result.stdout, (
            f'derived password contains forbidden character {c!r}: '
            f'{result.stdout!r}'
        )

@pytest.mark.xfail(reason='implementation not written yet')
def test_203_disable_repetition():
    runner = click.testing.CliRunner(mix_stderr=False)
    result = runner.invoke(derivepassphrase.cli.derivepassphrase,
                           ['--repeat', '0', '-p', DUMMY_SERVICE],
                           input=DUMMY_PASSPHRASE)
    assert result.exit_code == 0, (
        f'program died unexpectedly with exit code {result.exit_code}'
    )
    assert not result.stderr_bytes, (
        f'program barfed on stderr: {result.stderr_bytes}'
    )
    passphrase = result.stdout.rstrip('\r\n')
    for i in range(len(passphrase) - 1):
        assert passphrase[i:i+1] != passphrase[i+1:i+2], (
            f'derived password contains repeated character at position {i}: '
            f'{result.stdout!r}'
        )
