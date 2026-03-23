# Prerequisites for using `derivepassphrase vault` with an SSH key

Using `derivepassphrase vault` with an SSH key requires:

 1. [a running SSH agent](#ssh-agent),
 2. [a Python installation that can talk to the SSH
    agent](#python-support), and
 3. [a supported SSH key.](#ssh-key)

### A running SSH agent { #ssh-agent }

SSH agents are usually packaged as part of SSH client distributions.
Pageant from [PuTTY][] is known to work, on both UNIX and Windows.
`ssh-agent` from [OpenSSH][] is known to work well on UNIX, and
somewhat poorly on Windows; see notes below.
`gpg-agent` (v2) from [GnuPG][] is also known to work, but comes with
caveats; again, see notes below.

If in doubt, we recommend OpenSSH on UNIX and Pageant on Windows,
because they are the <i>de-facto</i> canonical SSH agent implementation
on their respective operating system.

!!! note "Agent-specific features"

    * OpenSSH's `ssh-agent` supports limiting the time the agent holds
      the key in memory ("key lifetime"), on UNIX only.
      We recommend its usage.
    * `ssh-agent` and GnuPG's `gpg-agent` support requiring confirmation
      upon each use for a specific key.
      (Again, for `ssh-agent` only on UNIX.)
      We recommend its usage as well.

<section markdown id=agent-specific-notes>

!!! note "Other agent-specific notes"

    === "OpenSSH on Windows"

        Using OpenSSH on Windows with `derivepassphrase vault` is
        possible, but currently *not recommended*.
        [The Windows port of OpenSSH lacks support for key constraints
        [1]][OPENSSH_ON_WINDOWS_NO_KEY_CONSTRAINTS_1]
        [[2]][OPENSSH_ON_WINDOWS_NO_KEY_CONSTRAINTS_2], which are the
        main advantage OpenSSH has over Pageant.
        Without this functionality, Pageant is the better choice: more
        supported key formats, manually lockable and unlockable key
        material in the agent, and no Administrator credentials needed
        to configure the system.

        Additionally, the ported SSH agent implements the agent
        protocol incorrectly because it terminates the connection when
        encountering an unsupported request, instead of returning an
        error code.
        (The original agent, on UNIX, implements the protocol
        correctly.)
        This makes it difficult for `derivepassphrase vault` to
        correctly *detect* or *verify* that it is talking to the
        OpenSSH agent on Windows, instead of merely *assuming* it is
        doing so.

    === "GnuPG/`gpg-agent`"

        ??? info "GnuPG terminology"

            GnuPG home directory
            :   The directory where GnuPG keeps its configuration;
                defaults to
                <code>C:\&#x200b;Users\&#x200b;&lt;username>\&#x200b;AppData\&#x200b;Roaming\&#x200b;gnupg</code>
                on Windows and <code>~/&#x200b;.gnupg</code> on POSIX.
                The user may set up multiple such directories.
                Agents are bound to a specific home directory;
                conversely, there can only be one agent per home
                directory.

            keygrip
            :   A GnuPG-specific fingerprint for cryptographic keys.
                Similar to the SSH key fingerprint, but not SSH-specific.

            `sshcontrol`
            :   A text file in the GnuPG home directory, listing the
                keygrips of SSH-compatible keys which `gpg-agent` knows
                about.
                `gpg-agent` will only advertise keys from this list if
                the corresponding private key is also known (on disk, on
                a smartcard, etc.).

        * `gpg-agent` v2.0 and later uses a *persistent* database of
          known keys, SSH or otherwise.
          "Adding" a key to the agent actually means *importing* it, and
          requires choosing an "import passphrase" to protect the key on
          disk, in the persistent database.
          `gpg-agent` will cache the import passphrase in memory, and if
          that cache entry expires, then the *import passphrase* must be
          provided to unlock the key.

        * The GnuPG distribution does not contain tools to generate
          native SSH keys or interactively add keys to a running
          `gpg-agent`, because its purpose is to expose keys in
          a different format (OpenPGP) to other (agent-compatible) SSH
          clients.
          A third-party tool (such as a full SSH client distribution) is
          necessary to load/import native SSH keys into `gpg-agent`.

        * As a design consequence of the persistent database,
          `gpg-agent` always lists all known SSH keys as available in
          the agent.
          It is impossible to remove an SSH key from `gpg-agent` using
          standard SSH agent operations.

            ??? info "Removing an SSH key from `gpg-agent` manually"

                The list of SSH-capable keys currently held by
                `gpg-agent` can be queried interactively with the
                `gpg-connect-agent` tool:

                === "SSH keys uploaded"

                    ~~~~ console linenums="1"
                    $ gpg-connect-agent 'KEYINFO --ssh-list --ssh-fpr=SHA256' /bye
                    S KEYINFO 04779A9B67BC8930046D9ABA86F1F85E1957D593 D - - 1 C SHA256:0h+WAokssfhzfzVyuMLJlIcWyCtk5WiXI8BHyhXYxC0 - S
                    S KEYINFO 9233C66A7A62D5866493F613D5F2E1A24343E048 D - - 1 C SHA256:1OHE0HrVlaSzJn2aQXQIKRu0tfO1CEMefy95K2Bt0xA - S
                    OK
                    ~~~~

                === "OpenPGP keys used as SSH keys"

                    ~~~~ console linenums="1"
                    $ gpg-connect-agent 'KEYINFO --list --with-ssh --ssh-fpr=SHA256' /bye
                    S KEYINFO 04779A9B67BC8930046D9ABA86F1F85E1957D593 D - - 1 C SHA256:0h+WAokssfhzfzVyuMLJlIcWyCtk5WiXI8BHyhXYxC0 - S
                    S KEYINFO 9233C66A7A62D5866493F613D5F2E1A24343E048 D - - 1 C SHA256:1OHE0HrVlaSzJn2aQXQIKRu0tfO1CEMefy95K2Bt0xA - S
                    OK
                    ~~~~

                The agent identifies cryptographic keys (of any kind) by
                the keygrip (the third entry on each line, so
                `04779A9B67BC8930046D9ABA86F1F85E1957D593` for the first
                key and `9233C66A7A62D5866493F613D5F2E1A24343E048` for
                the second key in the snippet above).
                By matching the SSH fingerprint (the ninth entry on each
                line), we can then determine the keygrip of the key we
                wish to remove from the agent:

                ~~~~ console linenums="6"
                > DELETE_KEY 04779A9B67BC8930046D9ABA86F1F85E1957D593
                OK
                > DELETE_KEY 9233C66A7A62D5866493F613D5F2E1A24343E048
                OK
                ~~~~

                (The agent will prompt for confirmation.)
                We can then confirm that the key is no longer loaded
                because the fourth entry changes from `D` ("on disk") to
                `-` ("missing"):

                ~~~~ console linenums="10"
                > KEYINFO --ssh-list --ssh-fpr=SHA256
                S KEYINFO 04779A9B67BC8930046D9ABA86F1F85E1957D593 - - - - - - - S
                S KEYINFO 9233C66A7A62D5866493F613D5F2E1A24343E048 - - - - - - - S
                OK
                > BYE
                OK closing connection
                ~~~~

                At this point, the keys are no longer available to the
                agent, but still "known" to the agent.
                To make `gpg-agent` "forget" them, the respective
                keygrip needs to be removed from `sshcontrol`.

        * `gpg-agent` does not advertise its communication socket by
          default, contrary to other SSH agents, so it must be manually
          advertised:

            === "UNIX"

                ~~~~ console
                $ SSH_AUTH_SOCK="$(gpgconf --list-dirs agent-ssh-socket)"
                $ export SSH_AUTH_SOCK
                ~~~~

            === "Windows (`libassuan` socket)"

                `gpg-agent` on Windows contains a native emulation of
                UNIX domain sockets by the `assuan` library, which GnuPG
                internally uses for network connectivity and
                inter-process communication.
                No specific configuration is necessary, and the agent
                address can be directly obtained with `gpgconf`:

                ~~~~ console
                $ gpgconf --list-dirs agent-ssh-socket
                ~~~~

                This mode, sadly, is not currently supported.
                The system is specific to GnuPG/`libassuan`, and
                unlikely to be deployed widely enough to make
                implementing this a priority for us… at least, relative
                to the other, more common interprocess communication
                channels for SSH agents on Windows.

            === "Windows (OpenSSH emulation)"

                From v2.4 onwards, `gpg-agent` supports masquerading as
                OpenSSH's `ssh-agent` on Windows, by passing the
                `--enable-win32-openssh-support` command-line argument
                to the agent.
                (Because of `gpg-agent`'s idiosyncratic autostart
                behavior, it is usually simpler to add the corresponding
                option `enable-win32-openssh-support` to the `gpg-agent`
                configuration file instead.)

                This mode is fully supported, at least as of GnuPG
                version 2.4.8.
                Note, however, that [the GnuPG developers consider this
                communication endpoint support experimental and
                untested][GPG_AGENT_OPENSSH_EMULATION_EXPERIMENTAL],[^gpg-agent-openssh-emulation-experimental]
                so it is unclear if GnuPG will continue to provide this
                masquerading functionality.

</section>

[^gpg-agent-openssh-emulation-experimental]: This experimental status is
    presumably specifically about the communication system in use
    (Windows named pipes), which is only available on Windows and thus
    impossible to test on other operating systems.
    The GnuPG developers appear to have insufficient access to Windows
    machines to continue testing and maintaining this subsystem.
    ([The same lack of access to Windows machines originally affected
    *our* development of SSH agent support on Windows for
    `derivepassphrase` as well.][BUG_WINDOWS_SSH_AGENT_SUPPORT])

[GPG_AGENT_OPENSSH_EMULATION_EXPERIMENTAL]: https://dev.gnupg.org/T8013#210624
[OPENSSH_ON_WINDOWS_NO_KEY_CONSTRAINTS_1]: https://github.com/PowerShell/Win32-OpenSSH/issues/1056#issuecomment-362494167 "Issue #1056: ssh-agent should support '-c' and '-t' options of ssh-add"
[OPENSSH_ON_WINDOWS_NO_KEY_CONSTRAINTS_2]: https://github.com/PowerShell/Win32-OpenSSH/issues/2314#issuecomment-2529160589 'Issue #2314: Adding key with confirmation option to ssh-agent gives "agent refused operation"'

### A Python installation that can talk to the SSH agent { #python-support }

On non-Windows operating systems, the SSH agent is expected to advertise
its communication socket via the `SSH_AUTH_SOCK` environment variable,
which is common procedure.
Therefore, [your Python installation must support UNIX domain
sockets][socket.AF_UNIX].

Since version 0.6, Windows is supported.
[Your Python installation must support interfacing with the Windows
system DLLs.][ctypes.WinDLL]
By default, like on non-Windows systems, the SSH agent is expected to
advertise its communication socket via the `SSH_AUTH_SOCK` environment
variable.
Alternatively, `derivepassphrase` can be configured to connect to the
well-known socket addresses of Pageant or the OpenSSH agent
instead.[^pageant-socket-address]

[^pageant-socket-address]: In particular, Pageant uses a non-constant,
    long and pseudo-random socket address that is ([by
    design][CAPABILITIES]) computationally infeasible to compute for
    other processes not running in the same user's session.
    This would be non-sensical to require the user to compute
    externally, then set `SSH_AUTH_SOCK` accordingly, instead of
    teaching `derivepassphrase` to compute the address itself.

[CAPABILITIES]: https://en.wikipedia.org/wiki/Capability-based_security

`derivepassphrase vault --version` will report on supported and on
unavailable features, including "master SSH key":[^feature-support]

[^feature-support]: This indicates support in principle, on this
    hardware/software/system combination, for interfacing with an SSH
    agent.
    At runtime, this could still fail, e.g. because the SSH agent isn't
    actually running, because `derivepassphrase` is trying to connect to
    the wrong address, etc.

=== "supported"

    ~~~~ console
    $ derivepassphrase vault --version
    derivepassphrase 0.5
    Using cryptography 44.0.0
    Using click 8.1.8

    Supported features: master SSH key.
    ~~~~

=== "unavailable"

    ~~~~ console
    $ derivepassphrase vault --version
    derivepassphrase 0.5
    Using cryptography 44.0.0
    Using click 8.1.8

    Unavailable features: master SSH key.
    ~~~~

### A supported SSH key { #ssh-key }

For an SSH key to be usable by `derivepassphrase`, the SSH agent must
always generate the same signature for the same input, i.e. the
signature must be deterministic for this key type.
Commonly used SSH key types (as of January 2026) include [ECDSA][],
[Ed25519][], [RSA][], and, somewhat less commonly, [Ed448][] and
[DSA][].

  [RSA]: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
  [DSA]: https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
  [ECDSA]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
  [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
  [Ed448]: https://en.wikipedia.org/wiki/EdDSA#Ed448

* RSA, Ed25519 and Ed448 signatures are deterministic by definition.
  Thus RSA, Ed25519 and Ed448 keys are supported under any SSH agent
  that implements them.

* DSA and ECDSA signatures require choosing a value specific to each
  signature (a "cryptographic nonce"), which must be unpredictable.
  Typical DSA/ECDSA implementations therefore generate a suitably large
  random number as the nonce.
  This makes signatures non-deterministic, and thus unsuitable for
  `derivepassphrase`.

    ??? info "Exception: PuTTY/Pageant and RFC 6979"

        [RFC 6979][] specifies a method to *calculate* the nonce from
        the DSA/ECDSA key and the message to be signed.
        DSA/ECDSA signatures from SSH agents implementing RFC 6979 are
        therefore deterministic, and thus *also* suitable for
        `derivepassphrase`.
        Pageant 0.81 implements RFC 6979.

        !!! warning "Warning: Pageant < 0.81"

            Pageant 0.80 and earlier uses a different, homegrown method
            to calculate the nonce deterministically.
            Those versions are *also* prinicipally suitable for use with
            `derivepassphrase`, but **they generate different signatures
            -- and different derived passphrases -- than Pageant 0.81
            and later**.

??? info "What SSH key type do I have?"

    If, according to your SSH agent, your key's type…

      * …ends with `-cert-v01@openssh.com`, then, for the purposes of
        this list, ignore the `-cert-v01@openssh.com` suffix.
      * …is `dsa` or `ssh-dss`, or is `dsa` followed by a number, then
        your key type is **DSA**.
      * …is `rsa` or `ssh-rsa`, or is `rsa` followed by a number, then
        your key type is **RSA**.
      * …is `ecdsa` followed by a number, or is `ecdsa-sha2-nistp`
        followed by a number, then your key type is **ECDSA**.
      * …is `ssh-ed25519`, then your key type is **Ed25519**.
      * …is `ssh-ed448`, then your key type is **Ed448**.

If you do not yet have a (supported) SSH key, we recommend Ed25519 for
maximum speed and reasonable availability, otherwise RSA for maximum
availability.
We do not in general recommend Ed448 because it is not widely
implemented (as of January 2026).

??? example "Generating new SSH keys for `derivepassphrase`"

    === "OpenSSH"

        The resulting key will be stored in
        `~/.ssh/my-vault-ed25519-key`, using "vault key" as a comment.
        Replace `-t ed25519` with `-t rsa` if generating an RSA key, and
        adapt the filename accordingly.

        ~~~~ console
        $ ssh-keygen -t ed25519 -f ~/.ssh/my-vault-ed25519-key -C "vault key"
        Generating public/private ed25519 key pair.
        Enter passphrase for ".../.ssh/my-vault-ed25519-key" (empty for no passphrase): 
        Enter same passphrase again:
        Your identification has been saved in .../.ssh/my-vault-ed25519-key
        Your public key has been saved in .../.ssh/my-vault-ed25519-key.pub
        The key fingerprint is:
        SHA256:0h+WAokssfhzfzVyuMLJlIcWyCtk5WiXI8BHyhXYxC0 vault key
        The key's randomart image is:
        +--[ED25519 256]--+
        |o B=+            |
        |.=oE = .         |
        |.oX @ +          |
        | = + o * . .     |
        |  + o * S B      |
        |   + * + O o     |
        |      * o .      |
        |       o         |
        |                 |
        +----[SHA256]-----+
        ~~~~

        (The key fingerprint and the randomart image will naturally
        differ, as they are key-specific.)

    === "PuTTY"

        The resulting key will be stored in
        `~/.ssh/my-vault-ed25519-key.ppk`, using "vault key" as a comment.
        Replace `-t ed25519` with `-t rsa` if generating an RSA key, and
        adapt the filename accordingly.

        ~~~~ console
        $ puttygen -t ed25519 -o ~/.ssh/my-vault-ed25519-key.ppk -C "vault key"
        Enter passphrase to save key: 
        Re-enter passphrase to verify: 
        ~~~~

    === "GnuPG"

        Not supported natively.
        A different SSH client distribution such as OpenSSH or PuTTY is
        necessary to create SSH keys specifically.

        Alternatively, GnuPG supports reusing keys in its native OpenPGP
        format for SSH as long as the underlying key type is compatible.
        First, obtain the keygrip for the correct key you may want to
        use.
        ([See the agent-specific notes for GnuPG
        terminology.](#agent-specific-notes))

        ~~~~ console
        $ gpg --list-keys --with-keygrip sample-key@example.com
        sec   rsa4096 2026-01-21 [SC] [expires: 2026-01-24]
              375509534445A9CA834F15E21A1525F3334C607A
              Keygrip = D91EBFAC7C503623B8BCC628B5B5A233AD7CA219
        uid           [ultimate] Sample Key <sample-key@example.com>
        ssb   rsa4096 2026-01-21 [E] [expires: 2026-01-24]
              Keygrip = E3F1DC21B524B5515C16D8E6112F20F3810C64F2
        ~~~~

        (Note that OpenPGP *subkeys* have a different keygrip than the
        *main key*.
        Be sure to use the correct one, e.g.,
        D91EBFAC7C503623B8BCC628B5B5A233AD7CA219.)

        === "before v2.3.7"

            Add the keygrip (on a line of its own) to `sshcontrol`.

            ~~~~ console
            $ echo D91EBFAC7C503623B8BCC628B5B5A233AD7CA219 >> ~/.gnupg/sshcontrol
            ~~~~

        === "v2.3.7 and later"

            Set a key attribute to permit this key's use in SSH:

            ~~~~ console
            $ gpg-connect-agent 'KEYATTR D91EBFAC7C503623B8BCC628B5B5A233AD7CA219 Use-for-ssh: true' /bye
            OK
            ~~~~

---

!!! abstract "Further reading"

    → [How to set up `derivepassphrase vault` with an SSH key][HOWTO]

[HOWTO]: ../how-tos/ssh-key.md
[GnuPG]: https://gnupg.org/
[BUG_WINDOWS_SSH_AGENT_SUPPORT]: ../wishlist/windows-ssh-agent-support.md
[OpenSSH]: https://www.openssh.com/
[PuTTY]: https://www.chiark.greenend.org.uk/~sgtatham/putty/
[PYTHON_AF_UNIX]: https://docs.python.org/3/library/socket.html#socket.AF_UNIX
[RFC 6979]: https://www.rfc-editor.org/rfc/rfc6979
