# derivepassphrase(1)

## NAME

derivepassphrase – derive a strong passphrase, deterministically, from
a master secret

## SYNOPSIS

````
derivepassphrase [SUBCOMMAND_ARGS]...
````

## DESCRIPTION

Using a master secret, derive a passphrase for a named service,
subject to constraints e.g. on passphrase length, allowed
characters, etc.  The exact derivation depends on the selected
derivation scheme.  For each scheme, it is computationally
infeasible to discern the master secret from the derived passphrase.
The derivations are also deterministic, given the same inputs, thus
the resulting passphrases need not be stored explicitly.  The
service name and constraints themselves also generally need not be
kept secret, depending on the scheme.

The currently implemented subcommands are <b>vault</b> (for the scheme
used by vault) and <b>export</b> (for exporting foreign configuration
data).  See the respective `--help` output for instructions.  If no
subcommand is given, we default to <b>vault</b>.

## SUBCOMMANDS

[<b>export</b>][EXPORT_SUBCMD]
:   Export a foreign configuration to standard output.

[<b>vault</b>][VAULT_SUBCMD]
:   Derive a passphrase using the vault(1) derivation scheme.

## DEPRECATION NOTICE

Defaulting to <b>vault</b> is deprecated.  Starting in v1.0, the
subcommand must be specified explicitly.

## CONFIGURATION

Configuration is stored in a directory according to the
`$DERIVEPASSPHRASE_PATH` variable, which defaults to
`~/.derivepassphrase` on UNIX-like systems and
`C:\Users\<user>\AppData\Roaming\Derivepassphrase` on Windows.

## SEE ALSO

[derivepassphrase-export(1)][EXPORT_SUBCMD],
[derivepassphrase-vault(1)][VAULT_SUBCMD]

[EXPORT_SUBCMD]: derivepassphrase-export.1.md
[VAULT_SUBCMD]: derivepassphrase-export.1.md
