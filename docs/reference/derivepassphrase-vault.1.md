# derivepassphrase-vault(1)

## NAME

derivepassphrase-vault – derive a passphrase using the vault derivation scheme

## SYNOPSIS

<pre>
<code><b>derivepassphrase vault</b> [--phrase | --key] [--length <var>n</var>] [--repeat <var>n</var>] [--lower <var>n</var>] [--upper <var>n</var>] [--number <var>n</var>] [--space <var>n</var>] [--dash <var>n</var>] [--symbol <var>n</var>] <var>SERVICE</var></code>
<code><b>derivepassphrase vault</b> {--phrase | --key | … | --symbol <var>n</var>} … --config [--unset <var>setting</var> …] [--overwrite-existing | --merge-existing] [<var>SERVICE</var>]</code>
<code><b>derivepassphrase vault</b> {--notes <var>SERVICE</var> | --delete <var>SERVICE</var> | --delete-globals | --clear}</code>
<code><b>derivepassphrase vault</b> [--export-as {json | sh}] {--import <var>PATH</var> | --export <var>PATH</var>}</code>
</pre>

## DESCRIPTION

Using a master passphrase or a master SSH key, derive a passphrase for <var>SERVICE</var>, subject to length, character and character repetition constraints, in a manner compatible with James Coglan's <i>vault</i>(1).

The derivation is cryptographically strong, meaning that even if a single passphrase is compromised, guessing the master passphrase or a different service's passphrase is computationally infeasible.
The derivation is also deterministic, given the same inputs, thus the resulting passphrase need not be stored explicitly.

The service name and constraints themselves also need not be kept secret; the latter are usually stored in a world-readable file.

## OPTIONS

### Passphrase generation

The passphrase generation options can be divided into "passphrase source" options (`--phrase`, `--key`) and "passphrase constraint" options (all others).
The passphrase source options are mutually exclusive --- you may only specify one of them --- while the passphrase constraint options may be combined in any way.
The <var>SERVICE</var> is mandatory (see synopsis #1), unless the `--config` option is specified (see synopsis #2).
All character constraints refer to ASCII printable characters only (space (`U+0020`) to tilde (`U+007E`), excluding the grave accent (`U+0060`)).

<b>-p</b>, <b>-</b><b>-phrase</b>
:   Prompt for a passphrase.

    See also ["Configuration"](#configuration) for how this interacts with a stored passphrase or SSH key.

<b>-k</b>, <b>-</b><b>-key</b>
:   Select an SSH key.

    An SSH agent such as OpenSSH’s <i>ssh-agent</i>(1) or PuTTY’s <i>pageant</i>(1) must be running and accessible, and have the desired key loaded.
    The SSH key must also be <i>suitable</i> for this purpose; see ["SSH KEY SUITABILITY"](#ssh-key-suitability) for details.

    See also ["Configuration"](#configuration) for how this interacts with a stored passphrase or SSH key.

<b>-l</b> <var>n</var>, <b>-</b><b>-length</b> <var>n</var>
:   Force the passphrase to have the length <var>n</var>.
    Defaults to the length <b>20</b> if not specified, or if explicitly specified as <code>0</code>.

<b>-r</b> <var>n</var>, <b>-</b><b>-repeat</b> <var>n</var>
:   Permit only runs of up to <var>n</var> consecutive occurrences of the same character.
    Alternatively, forbid immediate additional repetitions of length <var>n</var> (or more) for any character in the derived passphrase.
    Setting <var>n</var> = `0` disables repetition constraints, which is the default.

<b>-</b><b>-lower</b> <var>n</var>
:   Include at least <var>n</var> lowercase characters in the derived passphrase.
    Setting <var>n</var> = `0` forbids these characters entirely.
    The default is to not constrain the occurrences in any manner.

<b>-</b><b>-upper</b> <var>n</var>
:   Include at least <var>n</var> uppercase characters in the derived passphrase.
    Setting <var>n</var> = `0` forbids these characters entirely.
    The default is to not constrain the occurrences in any manner.

<b>-</b><b>-number</b> <var>n</var>
:   Include at least <var>n</var> digits in the derived passphrase.
    Setting <var>n</var> = `0` forbids these characters entirely.
    The default is to not constrain the occurrences in any manner.

<b>-</b><b>-space</b> <var>n</var>
:   Include at least <var>n</var> spaces in the derived passphrase.
    Setting <var>n</var> = `0` forbids these characters entirely.
    The default is to not constrain the occurrences in any manner.

<b>-</b><b>-dash</b> <var>n</var>
:   Include at least <var>n</var> "dashes" (`-` or `_`) in the derived passphrase.
    Setting <var>n</var> = `0` forbids these characters entirely.
    The default is to not constrain the occurrences in any manner.

<b>-</b><b>-symbol</b> <var>n</var>
:   Include at least <var>n</var> symbols (any of `!"#$%&'()*+,./:;<=>?@[\]^{|}~-_`) in the derived passphrase.
    Setting <var>n</var> = `0` forbids these characters entirely, effectively also implying `--dash 0`.
    The default is to not constrain the occurrences in any manner.

### Configuration

The configuration options directly modify the stored settings: default settings, known services, and service-specific settings.
They are mutually exclusive; you may only specify one of them.
The <var>SERVICE</var> is mandatory for `--notes` and `--delete`, optional for `--config`, and forbidden for `--delete-globals` and `--clear` (see synopsis #2 and synopsis #3).

<b>-n</b>, <b>-</b><b>-notes</b>
:   Spawn an editor to edit notes for <var>SERVICE</var>.
    Use the `VISUAL` or `EDITOR` environment variables to configure the spawned editor.

<b>-c</b>, <b>-</b><b>-config</b>
:   Save the given settings for <var>SERVICE</var> (if given), or save the given settings as global default settings.

    See the ["Passphrase generation"](#passphrase-generation) and ["Compatibility and extension options"](#compatibility-and-extension-options) sections for other options compatible with `--config`.

    !!! danger

        Do **not** use the `--phrase` and `--config` options together.
        The configuration is assumed to *not contain sensitive contents*, and is *not encrypted*.

<b>-x</b>, <b>-</b><b>-delete</b>
:   Delete all stored settings for <var>SERVICE</var>.

<b>-</b><b>-delete-globals</b>
:   Delete all stored global default settings.

<b>-X</b>, <b>-</b><b>-clear</b>
:   Delete all stored settings.

### Storage management

The storage management options deal with importing and exporting the stored settings.
They are mutually exclusive; you may only specify one of them.
Using `-` as <var>PATH</var> for standard input/standard output is supported.

<b>-e</b> <var>PATH</var>, <b>-</b><b>-export</b> <var>PATH</var>
:   Export all saved settings into file <var>PATH</var>.

<b>-i</b> <var>PATH</var>, <b>-</b><b>-import</b> <var>PATH</var>
:   Import saved settings from file <var>PATH</var>.

### Compatibility and extension options

By default, <b>derivepassphrase vault</b> behaves in a manner compatible with <i>vault</i>(1).
The compatibility and extension options modify the behavior to enable additional functionality, or specifically to force compatibility.

<i>vault</i>(1) supports none of these options, and behaves as if the option had not been given or had been left in its default state.

<b>-</b><b>-overwrite-existing</b> / <b>-</b><b>-merge-existing</b>
:   When importing a configuration via `--import`, or configuring the settings via `--config`, overwrite or merge (<em>default</em>) the existing configuration.

    If overwriting the configuration, then the whole configuration (for `--import`) or the respective section (service-specific or global, for `--config`), will be written from scratch.
    If merging, then each section (service-specific or global, for `--import`) or each singular setting (for `--config`) will be overwritten, but other unaffected settings/sections will not.

    (<i>vault</i>(1) behaves as if `--merge-existing` were always given.)

<b>-</b><b>-unset</b> <var>setting</var>
:   When configuring via `--config`, also unset the specified <var>setting</var>, where <var>setting</var> is one of the passphrase generation settings (<code>phrase</code>, <code>key</code>, <code>lower</code>, …).
    May be specified multiple times.
    Must not overlap with any of the settings being set afterwards.

    (vault(1) does not support this option.)

<b>-</b><b>-export-as</b> \{ <b>json</b> | <b>sh</b> \}
:   When exporting the configuration via `--export`, export as JSON (default) or as a shell script in <i>sh</i>(1) format.

    The JSON format is compatible with <i>vault</i>(1).
    For the shell script format, see the ["SHELL SCRIPT EXPORT FORMAT"](#shell-script-export-format) section for details.

    (vault(1) behaves as if `--export-as json` were always given.)

### Other Options

<b>-</b><b>-version</b>
:   Show the version and exit.

<b>-h</b>, <b>-</b><b>-help</b>
:   Show a help message and exit.

## SHELL SCRIPT EXPORT FORMAT

If the shell script export format is selected, the configuration will be exported as a POSIX <i>sh</i>(1) script, containing calls to <b>derivepassphrase vault</b> to reconstruct the current configuration from scratch.
The script assumes a conforming <i>sh</i>(1), with support for "here" documents.

!!! danger

    **Do not run these emitted shell scripts directly without double-checking their output first!**

## SSH KEY SUITABILITY

An SSH key is <dfn>suitable</dfn> for use with <b>derivepassphrase vault</b> if the SSH agent guarantees that signatures produced with this key will be <em>deterministic</em>, given the same message to be signed.
This is a property specific to the key type, and sometimes the agent used:

  * RSA, Ed25519 and Ed448 keys are always suitable.
    OpenSSH’s <i>ssh-agent</i>(1) supports only these keys as suitable keys.

  * DSA and ECDSA keys are suitable if the SSH agent supports deterministic DSA signatures, e.g. by implementing RFC 6979.
    PuTTY’s <i>pageant</i>(1) supports this, in addition to the always-suitable keys mentioned above.

## ENVIRONMENT

`VISUAL`, `EDITOR`
:   <b>derivepassphrase vault</b> uses this editor to edit service notes when called with `--notes`.
    `VISUAL` has higher precedence than `EDITOR`.

`DERIVEPASSPHRASE_PATH`
:   <b>derivepassphrase</b> stores its configuration files and data in this directory.
    Defaults to `~/.derivepassphrase`.

## FILES

`$DERIVEPASSPHRASE_PATH/vault.json`
:   The stored configuration for <b>derivepassphrase vault</b>: the default passphrase generation settings, the known service names, and the service-specific settings.
    This file is <em>not</em> intended for the user to edit.

## SECURITY

!!! danger

      * There is **no way** to retrieve the generated passphrases if the master passphrase, the SSH key, or the exact passphrase settings are lost, short of trying out all possible combinations.
        You are **strongly** advised to keep independent backups of the settings and the SSH key, if any.

      * The configuration is **not** encrypted, and you are **strongly** discouraged from using a stored passphrase.

      * You are **strongly** advised to avoid the (shell script) configuration export format if possible, and use the JSON format instead.
        If you *must* use the shell script format, then **always** validate the export before attempting to interpret or run it.

## EXAMPLES

??? example "`derivepassphrase vault --phrase email`"

    Prompt for a master passphrase, then generate a standard passphrase (length 20, no character or repetition constraints) for the "email" service.

??? example "`derivepassphrase vault --key --upper 9 --lower 9 example.com`"

    Select an SSH key from the available suitable SSH keys in the running SSH agent, then generate a passphrase for the `example.com` service using the previously selected SSH key.
    The passphrase will have (standard) length 20, and at least nine characters will be uppercase characters and at least another nine characters will be lowercase characters.

??? example "`derivepassphrase example.com vault --key --upper 9 --lower 9 --number 9`"

    Attempt to generate a passphrase as in the previous example.
    This example will <em>error out</em>, because the passphrase constraints require at least 27 characters and the standard passphrase length 20 cannot accomodate this.

??? example "`derivepassphrase --config vault --key --upper 9 --lower 9 --space 2`"

    After selecting an SSH key, configure the default settings to use exactly nine uppercase characters, nine lowercase characters, and two spaces for each generated passphrase.
    (The specific service settings, or the command-line invocation, can still override these settings.)

??? example "`derivepassphrase vault example.com`"

    Because of the previous setting, the generated passphrase for the `example.com` service will behave as if `--key --upper 9 --lower 9 --space 2` had been specified during invocation (with the SSH key already having been selected).
    In particular, it is neither necessary to specify `--phrase` or `--key` nor is it necessary to actually select an SSH key or to type in a master passphrase.

## DIAGNOSTICS

The derivepassphrase vault utility exits 0 on success, and >0 if an error occurs.

## COMPATIBILITY

### With other software

<b>derivepassphrase vault</b> is <em>almost</em> drop-in compatible with James Coglan’s <i>vault</i>(1), version 0.3.0 (including "storeroom" support), meaning that each tool supports the same file formats and command-line arguments/options as the other one.

Exceptions:

  * <i>vault</i>(1) does not support the ["Compatibility and extension options"](#compatibility-and-extension-options) listed above.

  * <b>derivepassphrase vault</b> can import and generate configuration exports in the same format as <i>vault</i>(1), but it cannot <em>natively</em> read or write <i>vault</i>(1)'s configuration file (non-storeroom) or configuration directory (storeroom).
    (The sister command <i>derivepassphrase-export</i>(1) can read both these formats and export the contents.)

### Forward and backward compatibility

  * [Since v0.2.0.]
    In v1.0, the commands <b>derivepassphrase</b> and <b>derivepassphrase export</b> will require an explicit subcommand name.
    Both default to the subcommand <b>vault</b>.
  * [Since v0.2.0.]
    In v1.0, the configuration data file for the <b>vault</b> subcommand will be named `vault.json`, instead of `config.json`.
  * [Since v0.2.0, to be removed in v1.0.]
    An existing configuration data file `config.json` will be attempted to be renamed to `vault.json`.

## SEE ALSO

[<i>derivepassphrase</i>(1)](derivepassphrase.1.md),
[<i>pageant</i>(1)](https://www.chiark.greenend.org.uk/~sgtatham/putty/),
[<i>ssh-agent</i>(1)](https://www.openssh.com/),
[<i>vault</i>(1)](https://www.npmjs.com/package/vault "James Coglan's 'vault'").

## AUTHOR

[Marco Ricci](https://the13thletter.info) (`software` at `the13thletter` dot `info`)

## BUGS

  * The defaults are dictated by <i>vault</i>(1), necessitating the ["Compatibility and extension options"](#compatibility-and-extension-options). (WONTFIX.)

  * The Windows version does not support SSH keys because Python on Windows does not support the predominant type of inter-process communication used by SSH agents on Windows.
