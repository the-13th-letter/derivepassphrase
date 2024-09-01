## Man pages

* [`derivepassphrase(1)`][cli_man]: A deterministic, stateless password manager: command-line tool.

## Modules and packages

* `derivepassphrase`: Work-alike for vault(1) – deterministic, stateless password manager.
    * [`derivepassphrase.cli`][cli_module]: Command-line interface for `derivepassphrase`.
    * [`derivepassphrase.exporter`][]: Exporter for other passphrase generator configurations.
        * [`derivepassphrase.exporter.storeroom`][]: Exporter for the vault "storeroom" configuration format.
        * [`derivepassphrase.exporter.vault_native`][]: Exporter for the vault native configuration formats (v0.2 and v0.3).
    * [`derivepassphrase.sequin`][sequin]: Python port of Sequin, a pseudorandom number generator.
    * [`derivepassphrase.ssh_agent`][ssh_agent]: A bare-bones SSH agent client supporting signing and key listing.
    * [`derivepassphrase._types`][types_module]: Types used by `derivepassphrase`.
    * [`derivepassphrase.vault`][vault_module]: Python port of the vault(1) password generation scheme.

  [cli_man]: reference/derivepassphrase.1.md
  [cli_module]: reference/derivepassphrase.md
  [sequin]: reference/sequin.md
  [ssh_agent]: reference/ssh_agent.md
  [types_module]: reference/types.md
  [vault_module]: reference/vault.md
