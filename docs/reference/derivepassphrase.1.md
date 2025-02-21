# derivepassphrase(1)

## NAME

derivepassphrase – derive a strong passphrase, deterministically, from a master secret

## SYNOPSIS

````
derivepassphrase SUBCOMMAND_ARGS ...
````

## DESCRIPTION

Using a master secret, derive a passphrase for a named service, subject to constraints e.g. on passphrase length, allowed characters, etc.
The exact derivation depends on the selected derivation scheme.
Each scheme derives *strong* passphrases by design: the derived passphrases have as much entropy as permitted by the master secret and the passphrase constraints (whichever is more restrictive), and even if multiple derived passphrases are compromised, the master secret remains cryptographically difficult to discern from those compromised passphrases.
The derivations are also deterministic, given the same inputs, thus the resulting passphrases need not be stored explicitly.
The service name and constraints themselves also generally need not be kept secret, depending on the scheme.

## SUBCOMMANDS

[<b>export</b>][EXPORT_SUBCMD]
:   Export a foreign configuration to standard output.

[<b>vault</b>][VAULT_SUBCMD]
:   Derive a passphrase using the <i>vault</i>(1) derivation scheme.

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
:   Show version and feature information, then exit.

<b>-h</b>, <b>-</b><b>-help</b>
:   Show a help message, then exit.

## ENVIRONMENT

`DERIVEPASSPHRASE_PATH`
:   <b>derivepassphrase</b> stores its configuration files and data in this directory.
    Defaults to `~/.derivepassphrase` on UNIX-like systems and `C:\Users\<user>\AppData\Roaming\Derivepassphrase` on Windows.

## COMPATIBILITY

### With other software

Some derivation schemes are based on other software.
See their respective manpages for compatibility information.

Affected derivation schemes: <b>vault</b>.

### Forward and backward compatibility

  * [Since v0.2.0.] In v1.0, <b>derivepassphrase</b> will require an explicit subcommand name.
    Defaults to the subcommand <b>vault</b>.

## SEE ALSO

[<i>derivepassphrase-export</i>(1)][EXPORT_SUBCMD],
[<i>derivepassphrase-vault</i>(1)][VAULT_SUBCMD].

## AUTHOR

[Marco Ricci](https://the13thletter.info) (`software` at `the13thletter` dot `info`)

[EXPORT_SUBCMD]: derivepassphrase-export.1.md
[VAULT_SUBCMD]: derivepassphrase-vault.1.md
