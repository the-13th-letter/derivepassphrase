---
title: Reference overview
---

## Man pages

* [`derivepassphrase(1)`][top_man]: Derive a strong passphrase, deterministically, from a master secret.
    * [`derivepassphrase-vault(1)`][top_man]: Derive a passphrase using the vault(1) derivation scheme.
    * [`derivepassphrase-export(1)`][export_man]: Export a foreign configuration to standard output.
        * [`derivepassphrase-export-vault(1)`][export_man]: Export a vault-native configuration to standard output.

## Modules and packages (API docs)

* `derivepassphrase`: Work-alike for vault(1) – deterministic, stateless password manager.
    * [`derivepassphrase.cli`][]: Command-line interface for `derivepassphrase`.
    * [`derivepassphrase.exporter`][]: Exporter for other passphrase generator configurations.
        * [`derivepassphrase.exporter.storeroom`][]: Exporter for the vault "storeroom" configuration format.
        * [`derivepassphrase.exporter.vault_native`][]: Exporter for the vault native configuration formats (v0.2 and v0.3).
    * [`derivepassphrase.sequin`][]: Python port of Sequin, a pseudorandom number generator.
    * [`derivepassphrase.ssh_agent`][]: A bare-bones SSH agent client supporting signing and key listing.
    * [`derivepassphrase._types`][]: Types used by `derivepassphrase`.
    * [`derivepassphrase.vault`][]: Python port of the vault(1) password generation scheme.

## Technical prerequisites

* Prerequisites for [using `derivepassphrase vault` with an SSH key][PREREQ_SSH_KEY]

  [top_man]: derivepassphrase.1.md
  [vault_man]: derivepassphrase-vault.1.md
  [export_man]: derivepassphrase-export.1.md
  [export_vault_man]: derivepassphrase-export-vault.1.md

  [PREREQ_SSH_KEY]: prerequisites-ssh-key.md
