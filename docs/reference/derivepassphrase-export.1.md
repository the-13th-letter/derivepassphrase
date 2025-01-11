# derivepassphrase-export(1)

## NAME

derivepassphrase-export – export a foreign configuration to standard output

## SYNOPSIS

````
derivepassphrase export SUBCOMMAND_ARGS ...
````

## DESCRIPTION

Read a foreign system configuration, extract all information from it, and export the resulting configuration to standard output.

## SUBCOMMANDS

[<b>vault</b>][VAULT_SUBCMD]
:    Export a <i>vault</i>(1)-native configuration to standard output.

If no subcommand is given, we default to <b>vault</b>.

## OPTIONS

<b>-</b><b>-debug</b>
:   Emit all diagnostic information to standard error, including progress, warning and error messages.

    Cancels the effect of any previous <b>-</b><b>-quiet</b> or <b>-</b><b>-verbose</b> options.
    Also applies to subcommands.

<b>-v</b>, <b>-</b><b>-verbose</b>
:   Emit extra/progress information to standard error, on top of warning and error messages.

    Cancels the effect of any previous <b>-</b><b>-debug</b> or <b>-</b><b>-quiet</b> options.
    Also applies to subcommands.

<b>-q</b>, <b>-</b><b>-quiet</b>
:   Suppress all other diagnostic output to standard error, except error messages.
    This includes warning messages.

    Cancels the effect of any previous <b>-</b><b>-debug</b> or <b>-</b><b>-verbose</b> options.
    Also applies to subcommands.

<b>-</b><b>-version</b>
:   Show the version and exit.

<b>-h</b>, <b>-</b><b>-help</b>
:   Show a help message and exit.

## ENVIRONMENT

`DERIVEPASSPHRASE_PATH`
:   <b>derivepassphrase</b> stores its configuration files and data in this directory.
    Defaults to `~/.derivepassphrase` on UNIX-like systems and `C:\Users\<user>\AppData\Roaming\Derivepassphrase` on Windows.

## COMPATIBILITY

### With other software

See the respective subcommand's manpage for compatibility information.

### Forward and backward compatibility

  * [Since v0.2.0.] In v1.0, <b>derivepassphrase export</b> will require an explicit subcommand name.
    Defaults to the subcommand <b>vault</b>.

## SEE ALSO

[<i>derivepassphrase</i>(1)](derivepassphrase.1.md),
[<i>derivepassphrase-export-vault</i>(1)][VAULT_SUBCMD].

## AUTHOR

[Marco Ricci](https://the13thletter.info) (`software` at `the13thletter` dot `info`)

[VAULT_SUBCMD]: derivepassphrase-export-vault.1.md
