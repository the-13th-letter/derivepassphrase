# derivepassphrase-export(1)

## NAME

derivepassphrase-export – export a foreign configuration to standard
output

## SYNOPSIS

````
derivepassphrase export [SUBCOMMAND_ARGS]...
````

## DESCRIPTION

Read a foreign system configuration, extract all information from
it, and export the resulting configuration to standard output.

The only available subcommand is <b>vault</b>, which implements the
vault-native configuration scheme.  If no subcommand is given, we
default to <b>vault</b>.

## SUBCOMMANDS

[<b>vault</b>][VAULT_SUBCMD]
:    Export a vault-native configuration to standard output.

## DEPRECATION NOTICE

Defaulting to <b>vault</b> is deprecated.  Starting in v1.0, the
subcommand must be specified explicitly.

## SEE ALSO

[derivepassphrase(1)](derivepassphrase.1.md),
[derivepassphrase-export-vault(1)]

[VAULT_SUBCMD]: derivepassphrase-export-vault.1.md
