# Prerequisites for using `derivepassphrase vault` with an SSH key

Using `derivepassphrase vault` with an SSH key requires:

 1. [a running SSH agent](#ssh-agent),
 2. [a Python installation that can talk to the SSH
    agent](#python-support), and
 3. [a supported SSH key.](#ssh-key)

### A running SSH agent { #ssh-agent }

SSH agents are usually packaged as part of SSH client distributions.
`ssh-agent` from [OpenSSH][] and Pageant from [PuTTY][] are known to
work. `gpg-agent` (v2) from [GnuPG][] is also known to work, but comes
with caveats; see notes below.

If in doubt, we recommend OpenSSH because it is the <i>de-facto</i>
canonical SSH agent implementation.

!!! note "Agent-specific features"

    * OpenSSH's `ssh-agent` supports limiting the time the agent holds
      the key in memory ("key lifetime").  We recommend its usage.
    * `ssh-agent` and GnuPG's `gpg-agent` support requiring confirmation
      upon each use for a specific key.  We recommend its usage as well.

<section markdown id=agent-specific-notes>

!!! note "Other agent-specific notes"

    === "GnuPG/`gpg-agent`"

        * `gpg-agent` v2.0 and later uses a *persistent* database of
          known keys, SSH or otherwise.  "Adding" a key to the agent
          actually means *importing* it, and requires choosing an
          "import passphrase" to protect the key on disk, in the
          persistent database.  `gpg-agent` will cache the import
          passphrase in memory, and if that cache entry expires, then
          the *import passphrase* must be provided to unlock the key.

        * The GnuPG distribution does not contain tools to generate
          native SSH keys or interactively add keys to a running
          `gpg-agent`, because its purpose is to expose keys in
          a different format (OpenPGP) to other (agent-compatible) SSH
          clients.  A third-party tool (such as a full SSH client
          distribution) is necessary to load/import native SSH keys into
          `gpg-agent`.

        * As a design consequence of the persistent database,
          `gpg-agent` always lists all known SSH keys as available in
          the agent.  It is impossible to remove an SSH key from
          `gpg-agent` using standard SSH agent operations.

        * `gpg-agent` does not advertise its communication socket by
          default, contrary to other SSH agents, so it must be manually
          advertised:

            ~~~~ console
            $ SSH_AUTH_SOCK="$(gpgconf --list-dirs agent-ssh-socket)"
            $ export SSH_AUTH_SOCK
            ~~~~

</section>

### A Python installation that can talk to the SSH agent { #python-support }

!!! bug "Windows is currently *not* supported"

    <i>→ Further details:</i> [Issue
    `the-13th-letter/derivepassphrase#13`: Support PuTTY/Pageant on
    Windows][ISSUE_WINDOWS_SUPPORT]

    The two major SSH agents on Windows (PuTTY/Pageant and OpenSSH) use
    <i>Windows named pipes</i> for communication, and Python on Windows
    does not inherently support named pipes.  Since no comprehensive
    third-party Python modules to interface with named pipes appear to
    exist, teaching `derivepassphrase` to use Windows named pipes
    will require us developers to write a custom low-level C module
    specific to this application---an unrealistic task if we lack both
    technical know-how for the named pipe API as well as Windows
    hardware to test any potential implementation on.

On non-Windows operating systems, the SSH agent is expected to advertise
its communication socket via the `SSH_AUTH_SOCK` environment variable,
which is common procedure.  Therefore, [your Python installation must
support UNIX domain sockets][socket.AF_UNIX].

### A supported SSH key { #ssh-key }

For an SSH key to be usable by `derivepassphrase`, the SSH agent must
always generate the same signature for the same input, i.e. the
signature must be deterministic for this key type.  Commonly used SSH
key types include [RSA][], [DSA][], [ECDSA][], [Ed25519][] and
[Ed448][].

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
availability.  We do not in general recommend Ed448 because it is not
widely implemented.

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

        Not supported natively.  An alternative SSH client distribution
        such as OpenSSH or PuTTY is necessary.

        Alternatively, GnuPG supports reusing keys in its native OpenPGP
        format for SSH as long as the underlying key type is compatible.

---

!!! abstract "Further reading"

    → [How to set up `derivepassphrase vault` with an SSH key][HOWTO]

[HOWTO]: ../how-tos/ssh-key.md
[GnuPG]: https://gnupg.org/
[ISSUE_WINDOWS_SUPPORT]: https://github.com/the-13th-letter/derivepassphrase/issues/13
[OpenSSH]: https://www.openssh.com/
[PuTTY]: https://www.chiark.greenend.org.uk/~sgtatham/putty/
[PYTHON_AF_UNIX]: https://docs.python.org/3/library/socket.html#socket.AF_UNIX
[RFC 6979]: https://www.rfc-editor.org/rfc/rfc6979
