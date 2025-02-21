# derivepassphrase-export-vault(1)

## NAME

derivepassphrase-export-vault – export a vault-native configuration to standard output

## SYNOPSIS

````
derivepassphrase export vault [-f FMT] [-k K] PATH
````

## DESCRIPTION

Read the <i>vault</i>(1)-native configuration at <i>PATH</i>, extract all information from it, and export the resulting configuration to standard output (as if using <i>vault</i>(1)'s <b>-</b><b>-export</b> option).
Depending on the configuration format, this may either be a file or a directory.
Supports the <i>vault</i>(1) `v0.2`, `v0.3` and `storeroom` formats, all of which inherently use encryption and integrity protection.

If <i>PATH</i> is explicitly given as `VAULT_PATH`, then use the `VAULT_PATH` environment variable to determine the correct path.
(Use `./VAULT_PATH` or similar to indicate a file/directory actually named `VAULT_PATH`.)

## OPTIONS

<b>-f</b>, <b>-</b><b>-format</b> <i>FMT</i>
:   Try the storage format <i>FMT</i>.
    May be given multiple times; the formats will be tried in order.

    By default, we first try `v0.3`, then `v0.2`, and finally `storeroom`.

<b>-k</b>, <b>-</b><b>-key</b> <i>K</i>
:   Use <i>K</i> as the storage master key.

    By default, we check the `VAULT_KEY`, `LOGNAME`, `USER` and `USERNAME` environment variables, and use the first one with a proper value (*and only the first one*).

<b>-</b><b>-debug</b>
:   Emit all diagnostic information to standard error, including progress, warning and error messages.

    Cancels the effect of any previous <b>-</b><b>-quiet</b> or <b>-</b><b>-verbose</b> options.

<b>-v</b>, <b>-</b><b>-verbose</b>
:   Emit extra/progress information to standard error, on top of warning and error messages.

    Cancels the effect of any previous <b>-</b><b>-debug</b> or <b>-</b><b>-quiet</b> options.

<b>-q</b>, <b>-</b><b>-quiet</b>
:   Suppress all other diagnostic output to standard error, except error messages.
    This includes warning messages.

    Cancels the effect of any previous <b>-</b><b>-debug</b> or <b>-</b><b>-verbose</b> options.

<b>-</b><b>-version</b>
:   Show version and feature information, then exit.

<b>-h</b>, <b>-</b><b>-help</b>
:   Show a help message, then exit.

## ENVIRONMENT

`DERIVEPASSPHRASE_PATH`
:   <b>derivepassphrase</b> stores its configuration files and data in this directory.
    Defaults to `~/.derivepassphrase` on UNIX-like systems and `C:\Users\<user>\AppData\Roaming\Derivepassphrase` on Windows.

`VAULT_PATH`
:   A default path, relative to the home directory, where to look for the configuration to load.

`VAULT_KEY`
:   A password with which the vault configuration is encrypted.
    The password is interpreted as a UTF-8 byte string.

`LOGNAME`, `USER`, `USERNAME`
:   Fallback values for `VAULT_KEY`.

## DIAGNOSTICS

The <b>derivepassphrase export vault</b> utility exits 0 on success, and >0 if an error occurs.

### Fatal error messsages on standard error

(`%s` indicates a variable part of the message.)

<!-- Message-ID: ErrMsgTemplate.CANNOT_PARSE_AS_VAULT_CONFIG -->
<!-- Message-ID: ErrMsgTemplate.CANNOT_PARSE_AS_VAULT_CONFIG_OSERROR -->
??? failure "`Cannot parse %s as a valid vault-native configuration file/directory`"

    The file or directory is not a valid vault-native configuration.
    Alternatively, the wrong format was assumed and/or the wrong master key was provided.

<!-- Message-ID: ErrMsgTemplate.INVALID_VAULT_CONFIG -->
??? failure "`Invalid vault config: %s`"

    The file or directory was successfully decrypted and decoded, but the resulting contents are not valid as a vault configuration.

<!-- Message-ID: ErrMsgTemplate.MISSING_MODULE -->
??? failure "`Cannot load the required Python module %s`"

    (Exactly what it says.)

## COMPATIBILITY

### With other software

<b>derivepassphrase export vault</b> fully supports reading the configuration formats used by <i>vault</i>(1) v0.3 and lower (formats `v0.2` and `v0.3`), as well as the `storeroom` format used in development builds after <i>vault</i>(1) v0.3 (`storeroom` version 1).

There is no corresponding "import" subcommand, nor is there support for writing configuration files or directories in any of the aforementioned formats.

## SEE ALSO

[<i>derivepassphrase</i>(1)](derivepassphrase.1.md),
[<i>vault</i>(1)](https://www.npmjs.com/package/vault).

## AUTHOR

[Marco Ricci](https://the13thletter.info) (`software` at `the13thletter` dot `info`)

## BUGS

  * There is no support for writing <i>vault</i>(1) configuration files or directories in any of the aforementioned formats.

    WONTFIX: two-way interoperability of configuration file disk formats is currently out of scope.
    Use the standard `--import` and `--export` options of both <i>vault</i>(1) and <b>derivepassphrase vault</b>.
