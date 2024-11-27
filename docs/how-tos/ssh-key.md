# How to set up `derivepassphrase vault` with an SSH key

!!! abstract "See also"

    → Tradeoffs between a master passphrase and a master SSH key (TODO)

## Prerequisites

!!! abstract "Further reading"

    → Full technical details: [Prerequisites for using `derivepassphrase
    vault` with an SSH key][PREREQ]

 1. A running SSH agent; typically provided by OpenSSH or PuTTY.
 2. A Python installation that can talk to the SSH agent.
 3. A supported SSH key; typically an RSA, Ed25519 or Ed448 key.

## Configuring `derivepassphrase vault` to use an SSH key

Assuming the prerequisites are satisfied, ensure that the SSH agent is
running, the SSH key is loaded into the agent, and the `SSH_AUTH_SOCK`
environment variable is correctly set up.  The exact commands depend on
the SSH agent in use.

=== "OpenSSH"

    ~~~~ console title="Typical setup commands: starting the agent and setting up SSH_AUTH_SOCK"
    $ eval `ssh-agent -s`
    Agent pid 12345
    ~~~~

    (The process ID emitted above is helpful for signalling the agent
    later, e.g. for termination.)

    ~~~~ console title="Typical setup commands: loading the key into the agent, with 900s timeout and requiring confirmation"
    $ ssh-add -t 900 -c ~/.ssh/my-vault-ed25519-key
    Enter passphrase for /home/user/.ssh/my-vault-ed25519-key (will confirm each use): 
    Identity added: /home/user/.ssh/my-vault-ed25519-key (vault key)
    Lifetime set to 900 seconds
    The user must confirm each use of the key
    ~~~~

    (Your key filename and key comment will likely differ.)

=== "PuTTY"

    ~~~~ console title="Typical setup commands: starting the agent and loading the key"
    $ eval `pageant -T ~/.ssh/my-vault-ed25519-key.ppk`
    Enter passphrase to load key 'vault key': 
    ~~~~

    (Your key filename and key comment will likely differ.  The agent
    should automatically shut down once this terminal session is over.)

=== "GnuPG"

    ~~~~ console title="Typical setup commands: enabling SSH agent support in GnuPG"
    $ # This is equivalent to passing --enable-ssh-support upon agent
    $ # startup.
    $ echo enable-ssh-support:0:1 | gpgconf --change-options gpg-agent
    ~~~~

    (Loading native SSH keys into `gpg-agent` requires a separate SSH
    agent client such as OpenSSH; see the [agent-specific notes in the
    prerequisites][PREREQ_AGENT_SPECIFIC_NOTES].)

    ~~~~ console title="Typical setup commands: loading the key into the agent with the OpenSSH tools"
    $ ssh-add -c ~/.ssh/my-vault-ed25519-key
    Enter passphrase for /home/user/.ssh/my-vault-ed25519-key (will confirm each use): 
    Identity added: /home/user/.ssh/my-vault-ed25519-key (vault key)
    The user must confirm each use of the key
    ~~~~

    (Your key filename and key comment may differ.)

Next, configure `derivepassphrase vault` to use the loaded SSH key.

=== "global key"

    ~~~~ console
    $ derivepassphrase vault --config -k
    Suitable SSH keys:
    [1] ssh-rsa ...feXycsvJZ2uaYRjMdZeJGNAnHLUGLkBscw5aI8=  test key without passphrase
    [2] ssh-ed448 ...BQ72ZgtPMckdzabiz7JbM/b0JzcRzGLMsbwA=  test key without passphrase
    [3] ssh-ed25519 ...gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2  test key without passphrase
    Your selection? (1-3, leave empty to abort): 3
    ~~~~

    (The prompt text will be "Use this key?" instead if there is only one
    suitable key.)

    Now `derivepassphrase vault` will automatically use the configured
    key globally, even without the `-k`/`--key` option.

=== "key specifically for <var>SERVICE</var>"

    ~~~~ console
    $ derivepassphrase vault --config -k SERVICE
    Suitable SSH keys:
    [1] ssh-rsa ...feXycsvJZ2uaYRjMdZeJGNAnHLUGLkBscw5aI8=  test key without passphrase
    [2] ssh-ed448 ...BQ72ZgtPMckdzabiz7JbM/b0JzcRzGLMsbwA=  test key without passphrase
    [3] ssh-ed25519 ...gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2  test key without passphrase
    Your selection? (1-3, leave empty to abort): 3
    ~~~~

    (The prompt text will be "Use this key?" instead if there is only one
    suitable key.)

    Now `derivepassphrase vault` will automatically use the configured
    key for <var>SERVICE</var>, even without the `-k`/`--key` option.

!!! abstract "Further reading"

    → Tradeoffs between a master passphrase and a master SSH key,
    section "Should I use one master SSH key, or many keys?" (TODO)

[PREREQ]: ../reference/prerequisites-ssh-key.md
[PREREQ_AGENT_SPECIFIC_NOTES]: ../reference/prerequisites-ssh-key.md#agent-specific-notes
