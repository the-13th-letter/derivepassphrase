# How to set up `derivepassphrase vault` with an SSH key

## Prerequisites

!!! abstract "See also"

    → Tradeoffs between a master passphrase and a master SSH key (TODO)

 1. [A running SSH agent; typically provided by OpenSSH or
    PuTTY.](#prereq-ssh-agent)
 2. [A Python installation that can talk to the SSH
    agent.](#prereq-python-support)
 3. [A supported SSH key; typically an RSA, Ed25519 or Ed448
    key.](#prereq-ssh-key)

### A running SSH agent { #prereq-ssh-agent }

Install an SSH agent, which is usually part of an SSH client
distribution.  `ssh-agent` from [OpenSSH][], Pageant from [PuTTY][] and
`gpg-agent` (v2) from [GnuPG][] are known to work.  If in doubt, choose
OpenSSH.

??? note "Agent-specific features"

    * OpenSSH's `ssh-agent` supports limiting the time the agent holds
      the key in memory ("key lifetime").  Such usage is *recommended*.
    * `ssh-agent` and GnuPG's `gpg-agent` support requiring confirmation
      upon each use for a specific key.  Such usage is *also
      recommended*.

??? note "Other agent-specific notes"

    === "GnuPG/`gpg-agent`"

        * `gpg-agent` v2.0 and later uses a *persistent* database of
          known keys, SSH or otherwise.  "Adding" a key to the agent
          actually means *importing* it, and requires choosing an
          "import passphrase" to protect the key on disk, in the
          persistent database.  `gpg-agent` will cache the import
          passphrase in memory, and if that cache entry expires, then
          the *import passphrase* must be provided to unlock the key.
        * As a design consequence, `gpg-agent` always lists all known
          SSH keys as available in the agent.  It is impossible to
          remove an SSH key from `gpg-agent` using standard SSH agent
          operations.

### A Python installation that can talk to the SSH agent { #prereq-python-support }

On non-Windows operating systems, your Python installation must support
UNIX domain sockets (the `socket.AF_UNIX` symbol).  The SSH agent must
expose its communication socket via the `SSH_AUTH_SOCK` environment
variable.

??? bug "Windows is currently *not* supported"

    [→ Issue `the-13th-letter/derivepassphrase#13`: Support
    PuTTY/Pageant on Windows][ISSUE_WINDOWS_SUPPORT]

    The two major SSH agents on Windows (PuTTY/Pageant and OpenSSH) use
    <i>Windows named pipes</i> for communication, and Python on Windows
    does not inherently support named pipes.  No comprehensive
    third-party modules to interface with named pipes appears to exist,
    so teaching `derivepassphrase` to use Windows named pipes will
    require us developers to write a custom (C?) module specific to this
    application---an unrealistic task if we lack both technical know-how
    for the named pipe API as well as Windows hardware to test any
    potential implementation on.

### A supported SSH key { #prereq-ssh-key }

For an SSH key to be usable by `derivepassphrase`, the SSH agent must
always generate the same signature for the same input, i.e. the
signature must be deterministic for this key type.  Commonly used SSH
types include RSA, DSA, ECDSA, Ed25519 and Ed448.

* RSA, Ed25519 and Ed448 signatures are deterministic by definition.
  Thus RSA, Ed25519 and Ed448 keys are suitable under any SSH agent.

* DSA and ECDSA signatures require choosing a value specific to each
  signature (a "cryptographic nonce"), which must be unpredictable.
  Typical DSA/ECDSA implementations therefore generate a suitably large
  random number as the nonce.  This makes signatures non-deterministic,
  and thus unsuitable for `derivepassphrase`.

    ??? info "Exception: PuTTY/Pageant and RFC 6979"

        [RFC 6979][] specifies a method to *calculate* the nonce from
        the DSA/ECDSA key and the message to be signed.  DSA/ECDSA
        signatures from SSH agents implementing RFC 6979 are therefore
        deterministic, and thus *also* suitable for `derivepassphrase`.
        Pageant 0.81 implements RFC 6979.

        !!! warning "Warning: Pageant < 0.81"

            Pageant 0.80 and earlier uses a different, homegrown method
            to calculate the nonce deterministically.  Those versions
            are *also* prinicipally suitable for use with
            `derivepassphrase`, but **they generate different signatures
            -- and different derived passphrases -- than Pageant 0.81
            and later**.

## Configuring `derivepassphrase vault` to use an SSH key

Assuming the [prerequisites above](#prerequisites) are satisfied, ensure
that the SSH agent is running, the SSH key is loaded into the agent, and
the `SSH_AUTH_SOCK` environment variable is correctly set up.  The exact
commands depend on the SSH agent in use.

=== "OpenSSH"

    ~~~~ console title="Typical setup commands"
    $ # Start the agent.  Also sets up the environment.
    $ eval `ssh-agent -s`
    Agent pid 12345
    $ # Add your key, with a 900s timeout and requiring confirmation.
    $ ssh-add -t 900 -c ~/.ssh/my-vault-ed25519-key
    Enter passphrase for /home/user/.ssh/my-vault-ed25519-key (will confirm each use): 
    Identity added: /home/user/.ssh/my-vault-ed25519-key (vault key)
    Lifetime set to 900 seconds
    The user must confirm each use of the key
    $ # The agent is ready to use.  Don't forget to terminate the agent
    $ # when you're done: `kill 12345`, or whatever the agent pid is.
    ~~~~

=== "PuTTY"

    ~~~~ console title="Typical setup commands"
    $ # Start the agent.  Also sets up the environment and adds your key.
    $ eval `pageant -T ~/.ssh/my-vault-ed25519-key.ppk`
    Enter passphrase to load key 'vault key': 
    $ # The agent is ready to use, and will persist until this console
    $ # is closed.
    ~~~~

=== "GnuPG"

    `gpg-agent` is mainly intended to reuse OpenPGP keys in SSH
    contexts.  Actually loading native SSH keys into `gpg-agent`
    requires a separate SSH agent client (such as OpenSSH).

    ~~~~ console title="Typical setup commands"
    $ # Enable SSH agent support in GnuPG; equivalent to passing
    $ # --enable-ssh-support upon agent startup.
    $ echo enable-ssh-support:0:1 | gpgconf --change-options gpg-agent
    $ # Add your key, requiring confirmation.  Here we use the OpenSSH
    $ # tools.
    $ ssh-add -c ~/.ssh/my-vault-ed25519-key
    Enter passphrase for /home/user/.ssh/my-vault-ed25519-key (will confirm each use): 
    Identity added: /home/user/.ssh/my-vault-ed25519-key (vault key)
    The user must confirm each use of the key
    $ # The agent is ready to use.
    ~~~~

Next, configure `derivepassphrase vault` to use the loaded SSH key.  (You
will be prompted to select the correct SSH key among the keys the agent
holds, unless there is only one suitable key.)

=== "global key"

    ~~~~ console
    $ derivepassphrase vault -k
    ~~~~

    Now `derivepassphrase vault` will automatically use the configured
    key globally, even without the `-k`/`--key` option.

=== "key specifically for <var>SERVICE</var>"

    ~~~~ console
    $ derivepassphrase vault -k SERVICE
    ~~~~

    Now `derivepassphrase vault` will automatically use the configured
    key for <var>SERVICE</var>, even without the `-k`/`--key` option.

[GnuPG]: https://gnupg.org/
[ISSUE_WINDOWS_SUPPORT]: https://github.com/the-13th-letter/derivepassphrase/issues/13
[OpenSSH]: https://www.openssh.com/
[PuTTY]: https://www.chiark.greenend.org.uk/~sgtatham/putty/
[PYTHON_AF_UNIX]: https://docs.python.org/3/library/socket.html#socket.AF_UNIX
[RFC 6979]: https://www.rfc-editor.org/rfc/rfc6979
