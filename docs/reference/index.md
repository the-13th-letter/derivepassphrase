---
title: Reference overview
---

## Man pages

* [`derivepassphrase(1)`][cli_man]: A deterministic, stateless password manager: command-line tool.
* [`derivepassphrase_export(1)`][export_man]: Export a vault-native configuration to standard output.

## Modules and packages

* `derivepassphrase`: Work-alike for vault(1) – deterministic, stateless password manager.
    * [`derivepassphrase.cli`][]: Command-line interface for `derivepassphrase`.
    * [`derivepassphrase.exporter`][]: Exporter for other passphrase generator configurations.
        * [`derivepassphrase.exporter.storeroom`][]: Exporter for the vault "storeroom" configuration format.
        * [`derivepassphrase.exporter.vault_native`][]: Exporter for the vault native configuration formats (v0.2 and v0.3).
    * [`derivepassphrase.sequin`][]: Python port of Sequin, a pseudorandom number generator.
    * [`derivepassphrase.ssh_agent`][]: A bare-bones SSH agent client supporting signing and key listing.
    * [`derivepassphrase._types`][]: Types used by `derivepassphrase`.
    * [`derivepassphrase.vault`][]: Python port of the vault(1) password generation scheme.

  [cli_man]: derivepassphrase.1.md
  [export_man]: derivepassphrase_export.1.md
