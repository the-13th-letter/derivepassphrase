# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT
import click

import derivepassphrase as dpp

__author__ = dpp.__author__
__version__ = dpp.__version__

__all__ = ('derivepassphrase',)

prog_name = 'derivepassphrase'

@click.group(context_settings={"help_option_names": ["-h", "--help"]}, invoke_without_command=True)
@click.version_option(version=__version__, prog_name="derivepassphrase")
def derivepassphrase():
    click.echo("Hello world!")
