# derivepassphrase-vault(1)

## NAME

derivepassphrase-vault – derive a passphrase using the vault(1)
derivation scheme

## SYNOPSIS

````
derivepassphrase vault [OPTIONS] [SERVICE]
````

## DESCRIPTION

Using a master passphrase or a master SSH key, derive a passphrase for
<i>SERVICE</i>, subject to length, character and character repetition
constraints.  The derivation is cryptographically strong, meaning that even
if a single passphrase is compromised, guessing the master passphrase or
a different service's passphrase is computationally infeasible.  The
derivation is also deterministic, given the same inputs, thus the resulting
passphrase need not be stored explicitly. The service name and constraints
themselves also need not be kept secret; the latter are usually stored in
a world-readable file.

If operating on global settings, or importing/exporting settings, then
<i>SERVICE</i> must be omitted.  Otherwise it is required.

## OPTIONS

### Password generation

<b>-p</b>, <b>-</b><b>-phrase</b>
:   prompts you for your passphrase

<b>-k</b>, <b>-</b><b>-key</b>
:   uses your SSH private key to generate passwords

<b>-l</b>, <b>-</b><b>-length</b> <var>NUMBER</var>
:   emits password of length <var>NUMBER</var>

<b>-r</b>, <b>-</b><b>-repeat</b> <var>NUMBER</var>
:   allows maximum of <var>NUMBER</var> repeated adjacent chars

<b>-</b><b>-lower</b> <var>NUMBER</var>
:   includes at least <var>NUMBER</var> lowercase letters

<b>-</b><b>-upper</b> <var>NUMBER</var>
:   includes at least <var>NUMBER</var> uppercase letters

<b>-</b><b>-number</b> <var>NUMBER</var>
:   includes at least <var>NUMBER</var> digits

<b>-</b><b>-space</b> <var>NUMBER</var>
:   includes at least <var>NUMBER</var> spaces

<b>-</b><b>-dash</b> <var>NUMBER</var>
:   includes at least <var>NUMBER</var> `-` or `_`

<b>-</b><b>-symbol</b> <var>NUMBER</var>
:   includes at least <var>NUMBER</var> symbol chars

Use <var>NUMBER</var>=0, e.g. `--symbol 0`, to exclude a character type from
the output.

### Configuration

<b>-n</b>, <b>-</b><b>-notes</b>
:   spawn an editor to edit notes for <var>SERVICE</var>

<b>-c</b>, <b>-</b><b>-config</b>
:   saves the given settings for <var>SERVICE</var> or global

<b>-x</b>, <b>-</b><b>-delete</b>
:   deletes settings for <var>SERVICE</var>

<b>-</b><b>-delete-globals</b>
:   deletes the global shared settings

<b>-X</b>, <b>-</b><b>-clear</b>
:   deletes all settings

Use `$VISUAL` or `$EDITOR` to configure the spawned editor.

### Storage management

<b>-e</b>, <b>-</b><b>-export</b> <var>PATH</var>
:   export all saved settings into file <var>PATH</var>

<b>-i</b>, <b>-</b><b>-import</b> <var>PATH</var>
:   import saved settings from file <var>PATH</var>

Using `-` as <var>PATH</var> for standard input/standard output is supported.

### Other Options

<b>--version</b>
:   Show the version and exit.

<b>-h</b>, <b>-</b><b>-help</b>
:   Show this message and exit.

## WARNINGS

There is **no way** to retrieve the generated passphrases if the master
passphrase, the SSH key, or the exact passphrase settings are lost,
short of trying out all possible combinations.  You are **strongly**
advised to keep independent backups of the settings and the SSH key, if
any.

The configuration is **not** encrypted, and you are **strongly**
discouraged from using a stored passphrase.

## SEE ALSO

[derivepassphrase(1)](derivepassphrase.1.md),
[vault(1)](https://www.npmjs.com/package/vault)
