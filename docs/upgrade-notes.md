# Upgrade notes for `derivepassphrase`

(Oldest version first.)

## Upgrading to 1.0 {#upgrading-to-v1.0}

### Remove implicit subcommand calls {#v1.0-implied-subcommands}

`derivepassphrase` will throw an error if the selected command or subcommand requires a subcommand of its own.
This affects `derivepassphrase` and `derivepassphrase export`.

~~~~ shell-session
$ derivepassphrase -p service-name        # deprecated
$ derivepassphrase export -f v0.2 .vault  # deprecated
~~~~

To avoid this, specify the subcommand explicitly.
The default subcommand in both cases is `vault`, so use `derivepassphrase vault ...` and `derivepassphrase export vault ...` instead.

~~~~ shell-session
$ derivepassphrase vault -p service-name
$ derivepassphrase export vault -f v0.2 .vault
~~~~

### Do not use the old `settings.json` config file {#v1.0-old-settings-file}

`derivepassphrase` has multiple subcommands.
The old settings file `$DERIVEPASSPHRASE_PATH/settings.json` suggests that this is a global file for `derivepassphrase`, but in fact it is specific to the `vault` subcommand.

Do not use this file; use the `vault` subcommand-specific configuration file `$DERIVEPASSPHRASE_PATH/vault.json` instead.
The file format is identical.
Existing `settings.json` files can be renamed to `vault.json` directly.

`derivepassphrase` versions between 0.2.0 (inclusive) and 1.0 (exclusive) will attempt to migrate/rename the file automatically.

### Do not use the `allow_derivepassphrase_extensions` vault config validator option {#v1.0-allow-derivepassphrase-extensions}

The `allow_derivepassphrase_extensions` keyword argument to [`derivepassphrase._types.validate_vault_config`][] is without effect since `derivepassphrase` version 0.4.0.
No extensions are defined as of version 0.4.0.

The only historic extension ever defined, which deals with storing Unicode normalization preferences, is a configuration option in the user configuration file in version 0.4.0 and higher:
`vault.SERVICE.unicode-normalization-form` (if set) for the service <var>SERVICE</var>, otherwise `vault.default-unicode-normalization-form`.
The latter defaults to `"NFC"`.
