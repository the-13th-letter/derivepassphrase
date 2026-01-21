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
running, the SSH key is loaded into the agent, and that
`derivepassphrase` knows how to obtain the agent's socket address:

- On UNIX systems, the `SSH_AUTH_SOCK` environment variable must be
  correctly set up.
- On Windows systems, by default, the `SSH_AUTH_SOCK` environment
  variable must be correctly set up.
  Alternatively, `derivepassphrase` can be explicitly configured to
  connect to OpenSSH or Pageant (PuTTY) without consulting
  `SSH_AUTH_SOCK`, in which case OpenSSH or Pageant must be running.

The exact commands depend on the SSH agent in use.

!!! info "Setup commands"

    === "OpenSSH"

        === "on UNIX"

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

        === "on Windows"

            ([Using OpenSSH on Windows is possible, but currently *not
            recommended*; we recommend Pageant
            instead.][OPENSSH_ON_WINDOWS_LIMITATIONS])

            The agent is started as a system service.
            This only needs to be set up once.

            <small>([Source: OpenSSH-on-Windows
            documentation][OPENSSH_ON_WINDOWS_DOC].)</small>

            ~~~~ pwsh-session title="Typical setup commands (PowerShell, as Administrator): starting the agent"
            PS> Get-Service ssh-agent | Set-Service -StartupType Automatic
            PS> Start-Service ssh-agent
            ~~~~

            Load the keys into the agent.
            This only needs to be done once.
            The agent stores the key material in a reusable, per-user
            Windows security context.
            Unlike on UNIX, the Windows port of OpenSSH does not support key
            timeouts or key usage confirmation prompts.

            ~~~~ pwsh-session title="Further setup commands (Powershell, as User): loading the key into the agent"
            PS> ssh-add "C:\Users\YourUsernameHere\Documents\my-vault-ed25519-key"
            Enter passphrase for C:\Users\YourUsernameHere\Documents\my-vault-ed25519-key:
            Identity added: C:\Users\YourUsernameHere\Documents\my-vault-ed25519-key (vault key)
            ~~~~

            (Your key filename and key comment will likely differ.)

            Finally, inform `derivepassphrase` about the OpenSSH agent's
            address:

            === "`openssh_on_windows` socket provider"

                Edit the file
                <code>C:\&#x200b;Users\&#x200b;&lt;username>&#x200b;AppData\&#x200b;Roaming\&#x200b;derivepassphrase\&#x200b;config.toml</code>
                and set the key `vault.ssh-agent-socket-provider` to
                `openssh_on_windows`:

                ~~~~ toml title="config.toml"
                [vault]
                ssh-agent-socket-provider = "openssh_on_windows"
                ~~~~

            === "`SSH_AUTH_SOCK` on Windows (not recommended)"

                (The "native" SSH agent socket provider must be in use.)

                ~~~~ pwsh-session title="Further setup commands (Powershell, as User): setting SSH_AUTH_SOCK"
                PS> $env:SSH_AUTH_SOCK = "\\.\pipe\openssh-ssh-agent"
                ~~~~

    === "PuTTY"

        === "on Windows"

            Start Pageant; this adds the Pageant icon to the Windows task
            bar.
            Then add the key via the right-click context menu, "Add key" or
            "Add key (encrypted)".

            Adding the key via "Add key (encrypted)" makes the key material
            manually "lockable" and "unlockable" by decrypting and
            re-encrypting it, meaning that the key cannot be used by
            malicious clients while encrypted.
            This can be used to partially alleviate the lack of support for
            the "key timeout" constraint.
            The "Add key (encrypted)" mode is thus *recommended*.

            Finally, inform `derivepassphrase` about the Pageant's address:

            === "`pageant_on_windows` socket provider"

                Edit the file
                <code>C:\&#x200b;Users\&#x200b;&lt;username>&#x200b;AppData\&#x200b;Roaming\&#x200b;derivepassphrase\&#x200b;config.toml</code>
                and set the key `vault.ssh-agent-socket-provider` to
                `pageant_on_windows`:

                ~~~~ toml title="config.toml"
                [vault]
                ssh-agent-socket-provider = "pageant_on_windows"
                ~~~~

            === "`SSH_AUTH_SOCK` on Windows (not recommended)"

                (The "native" SSH agent socket provider must be in use.)

                Pageant's address is unfortunately not fixed.
                To get Pageant to write out its socket address on startup,
                start it with the `--openssh-config <filename>` option to
                write an OpenSSH-compatible configuration snippet to
                `<filename>`, which includes the address.

                ~~~~ pwsh-session title="Further setup commands (Powershell, as User): setting SSH_AUTH_SOCK"
                PS> pageant --openssh-config file.conf
                PS> 
                PS> # Now read file.conf to learn the address; it looks like
                PS> # "\\.\pipe\pageant.<username>.0123456789abcdef..."
                PS>
                PS> $env:SSH_AUTH_SOCK = "\\.\pipe\pageant.YourUsernameHere.0123456789deadbeef..."
                ~~~~

        === "on UNIX"

            ~~~~ console title="Typical setup commands: starting the agent and loading the key"
            $ eval `pageant -T ~/.ssh/my-vault-ed25519-key.ppk`
            Enter passphrase to load key 'vault key': 
            ~~~~

            (Your key filename and key comment will likely differ.
            The agent should automatically shut down once this terminal
            session is over.)

    === "GnuPG"

        === "on UNIX"

            ~~~~ console title="Typical setup commands: enabling SSH agent support in GnuPG"
            $ # This is equivalent to passing --enable-ssh-support upon agent
            $ # startup.
            $ echo enable-ssh-support:0:1 | gpgconf --change-options gpg-agent
            $ # Then export the SSH_AUTH_SOCK environment variable appropriately.
            $ export SSH_AUTH_SOCK="$(gpgconf --list-dirs agent-ssh-socket)"
            ~~~~

            (Loading native SSH keys into `gpg-agent` requires
            a separate SSH agent client such as OpenSSH; see the
            [agent-specific notes in the
            prerequisites][PREREQ_AGENT_SPECIFIC_NOTES].)

            ~~~~ console title="Typical setup commands: loading the key into the agent with the OpenSSH tools"
            $ ssh-add -c ~/.ssh/my-vault-ed25519-key
            Enter passphrase for /home/user/.ssh/my-vault-ed25519-key (will confirm each use): 
            Identity added: /home/user/.ssh/my-vault-ed25519-key (vault key)
            The user must confirm each use of the key
            ~~~~

            (Your key filename and key comment may differ.)

        === "on Windows"

            Edit the file `gpg-agent.conf` in the GnuPG home directory to
            contain the line `enable-win32-openssh-support`, which is
            equivalent to passing `--enable-win32-openssh-support` upon
            agent startup.
            This causes `gpg-agent` to masquerade as OpenSSH`s agent.

            Then, inform `derivepassphrase` about the agent's address,
            i.e., of the OpenSSH agent's socket address:

            === "`openssh_on_windows` socket provider"

                Edit the file
                <code>C:\&#x200b;Users\&#x200b;&lt;username>&#x200b;AppData\&#x200b;Roaming\&#x200b;derivepassphrase\&#x200b;config.toml</code>
                and set the key `vault.ssh-agent-socket-provider` to
                `openssh_on_windows`:

                ~~~~ toml title="config.toml"
                [vault]
                ssh-agent-socket-provider = "openssh_on_windows"
                ~~~~

            === "`SSH_AUTH_SOCK` on Windows (not recommended)"

                (The "native" SSH agent socket provider must be in use.)

                ~~~~ pwsh-session title="Further setup commands (Powershell, as User): setting SSH_AUTH_SOCK"
                PS> $env:SSH_AUTH_SOCK = "\\.\pipe\openssh-ssh-agent"
                ~~~~

            (Loading native SSH keys into `gpg-agent` requires
            a separate SSH agent client such as OpenSSH; see the
            [agent-specific notes in the
            prerequisites][PREREQ_AGENT_SPECIFIC_NOTES].)

            ~~~~ console title="Typical setup commands (PowerShell): loading the key into the agent with the OpenSSH tools"
            $ ssh-add "C:\Users\YourUsernameHere\Documents\my-vault-ed25519-key"
            Enter passphrase for C:\Users\YourUsernameHere\Documents\my-vault-ed25519-key (will confirm each use): 
            Identity added: C:\Users\YourUsernameHere\Documents\my-vault-ed25519-key (vault key)
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

[OPENSSH_ON_WINDOWS_LIMITATIONS]: ../reference/prerequisites-ssh-key.md#agent-specific-notes
[OPENSSH_ON_WINDOWS_DOC]: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement#user-key-generation

[PREREQ]: ../reference/prerequisites-ssh-key.md
[PREREQ_AGENT_SPECIFIC_NOTES]: ../reference/prerequisites-ssh-key.md#agent-specific-notes
