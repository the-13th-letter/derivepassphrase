# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Tests for the `derivepassphrase` command-line interface.

There are separate submodules for

  * [testing basic
  things][tests.test_derivepassphrase_cli.test_000_basic]

  * [common testing across all
  CLIs][tests.test_derivepassphrase_cli.test_all_cli]

  * [heavy-duty
  testing][tests.test_derivepassphrase_cli.test_heavy_duty]

  * [testing shell
  completion][tests.test_derivepassphrase_cli.test_shell_completion]

  * [testing transition functions and
  messages][tests.test_derivepassphrase_cli.test_transition]

  * [testing internal utility
  functions][tests.test_derivepassphrase_cli.test_utils]

  * [testing basic functionality of the `vault`
  CLI][tests.test_derivepassphrase_cli.test_vault_cli_basic_functionality]

  * [testing configuration management via the `vault`
  CLI][tests.test_derivepassphrase_cli.test_vault_cli_config_management]

  * [testing notes handling in the `vault`
  CLI][tests.test_derivepassphrase_cli.test_vault_cli_notes_handling]

"""
