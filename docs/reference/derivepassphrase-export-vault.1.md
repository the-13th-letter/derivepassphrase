# derivepassphrase-export-vault(1)

## NAME

derivepassphrase-export-vault – export a vault-native configuration to
standard output

## SYNOPSIS

````
derivepassphrase export vault [OPTIONS] PATH
````

## DESCRIPTION

Read the <b>vault</b>-native configuration at <i>PATH</i>, extract all
information from it, and export the resulting configuration to standard
output. Depending on the configuration format, this may either be a file or
a directory.  Supports the vault "v0.2", "v0.3" and "storeroom" formats.

If <i>PATH</i> is explicitly given as `VAULT_PATH`, then use the
`VAULT_PATH` environment variable to determine the correct path. (Use
`./VAULT_PATH` or similar to indicate a file/directory actually named
`VAULT_PATH`.)

## OPTIONS

<b>-f</b>, <b>-</b><b>-format</b> <i>FMT</i>
:    try the following storage formats, in order (default: `v0.3`, `v0.2`)

<b>-k</b>, <b>-</b><b>-key</b> <i>K</i>
:    use <i>K</i> as the storage master key (default: check the `VAULT_KEY`,
     `LOGNAME`, `USER` or `USERNAME` environment variables)

<b>-h</b>, <b>-</b><b>-help</b>
:    Show this message and exit.

## ENVIRONMENT VARIABLES

<b>VAULT_PATH</b>
:   A default path, relative to the home directory, where to look for the
    configuration to load.

<b>VAULT\_KEY</b>
:   A password with which the vault configuration is encrypted.  The
    password is interpreted as a UTF-8 byte string.

<b>LOGNAME</b>, <b>USER</b>, <b>USERNAME</b>
:   Fallback values for `VAULT_KEY`.

## SEE ALSO

[derivepassphrase(1)](derivepassphrase.1.md),
[vault(1)](https://www.npmjs.com/package/vault)
