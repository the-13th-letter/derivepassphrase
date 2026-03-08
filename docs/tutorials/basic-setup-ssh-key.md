# Using a master SSH key with `derivepassphrase vault` on existing accounts

!!! abstract "See also"

    → [Tutorial: Setting up `derivepassphrase vault` for three accounts, with a master passphrase][BASIC_SETUP_PASSPHRASE]

    → Tradeoffs between a master passphrase and a master SSH key (TODO)

## The scenario

This tutorial builds upon the previous [tutorial for setting up `derivepassphrase vault` for three accounts, with a master passphrase][BASIC_SETUP_PASSPHRASE].
We have a working `derivepassphrase` installation, and a `derivepassphrase vault` configuration for three services `email`, `bank` and `work`, using a master passphrase.

## Installing `derivepassphrase` with SSH key support

??? note "Note: Shell Notation"

    `derivepassphrase` is a command-line application: it runs in the system shell, such as `/bin/sh` on UNIX and Powershell on Windows.

    In the following shell session transcripts, `$` and '>' denote the <b>prompt</b> from the system shell for user input.
    Type in *the remainder* of line, but not the prompt itself.
    Other lines are *output lines*, which should appear on your shell.

    For Windows-specific commands, we use the `PS>` prompt; otherwise, we use UNIX-style `$` and `>` prompts.

[You have already installed `derivepassphrase`.](basic-setup-passphrase.md#installing-derivepassphrase)
Once again, check that the installation was successful.

~~~~ shell-session
$ devirepassphrase vault --version
derivepassphrase 0.5
Using cryptography 44.0.0
Using click 8.1.8

Supported features: master SSH key.
~~~~

(…or similar output.)
Furthermore, verify that "master SSH key" is among the listed supported features.[^no-support]
Without support for SSH keys, this tutorial cannot be completed.

[^no-support]: If "master SSH key" is not listed as a supported feature, then this `derivepassphrase` installation cannot use master SSH keys.
    Sorry.
    This likely means that we cannot talk to the SSH agent because it uses a communication channel that we cannot or don't know how to access.

## Setting up an SSH agent and SSH key generator

`derivepassphrase` cannot generate SSH keys or do SSH key operations itself; instead, it relies on widespread and well-tested third-party software such as OpenSSH or PuTTY for this purpose.
We need to install such software as well.

=== "UNIX (and Cygwin/MSYS, WSL, and Git for Windows)"

    You likely already have OpenSSH installed, or can easily install them via your package manager or via [the official OpenSSH distribution][OPENSSH].
    We only need access to the `ssh-agent`, `ssh-add` and `ssh-keygen` client tools; in particular, we do not need the OpenSSH server.

    ~~~~ shell-session title="Getting the version number of the installed OpenSSH client tools"
    $ ssh -V
    OpenSSH_10.2p1, OpenSSL 3.5.4 30 Sep 2025
    ~~~~

    Start an SSH agent if none is running yet.
    (Some desktop environments automatically launch an agent on startup.)
    We can check this via `ssh-add -l`.

    === "Could not open a connection…"

        ~~~~ shell-session
        $ ssh-add -l
        Could not open a connection to your authentication agent.
        ~~~~

        The agent is not running.
        So start an agent manually:

        ~~~~ shell-session
        $ eval "$(ssh-agent -s)"
        ~~~~

        and arrange for it to be shut down upon exiting this shell session:

        ~~~~ shell-session
        $ trap "kill $SSH_AGENT_PID" 0
        ~~~~

    === "The agent has no identities."

        ~~~~ shell-session
        $ ssh-add -l
        The agent has no identities.
        ~~~~

        The agent is already running.

    === "(numbers, random characters, …)"

        ~~~~ shell-session
        $ ssh-add -l
        256 SHA256:0h+WAokssfhzfzVyuMLJlIcWyCtk5WiXI8BHyhXYxC0  (ED25519)
        3072 SHA256:1OHE0HrVlaSzJn2aQXQIKRu0tfO1CEMefy95K2Bt0xA  (RSA)
        ~~~~

        (… or similar output, perhaps with text.)

        The agent is running, and already contains some keys.

=== "Windows"

    <div style="float: right;">

    <figure markdown>
    ![A CRT monitor wearing a spy hat.][PAGEANT_ICON]{ width="96" }
    <figcaption>
    [The `pageant` icon][PUTTY_ICON_HISTORY]
    </figcaption>
    </figure>

    </div>

    Install PuTTY e.g. from [the official PuTTY distribution][PUTTY] website, or from the Microsoft Store (if supported).
    We only need access to the `pageant` and `puttygen` tools.

    Start `pageant` if it isn't running yet.
    An icon of a CRT computer monitor wearing a black hat should appear in the task bar.

[PAGEANT_ICON]: pageant.svg
[PUTTY_ICON_HISTORY]: https://www.chiark.greenend.org.uk/~sgtatham/quasiblog/putty-icons/

## Generating a master SSH key, and loading it into the agent

!!! abstract "Further reading"

    → [Prerequisites for the SSH key, for use with `derivepassphrase
    vault`][PREREQ_SSH_KEY]

??? warning "Operational risk: reusing &quot;login&quot; SSH keys for passphrase derivation"

    SSH keys are typically used as access tokens for logging in on a remote system.
    You are **discouraged** from reusing such an existing "login" key for passphrase derivation.
    A master SSH key is a **long-lived secret**, and should **never need to be rotated, unless compromised or lost**.
    Rotating a master SSH key means **forcibly changing all passphrases that are derived from this key**.
    By contrast, a login SSH key is an access token, and may be rotated for other policy-related reasons (e.g. "upgrades" to a different algorithm, consolidation of multiple keys into a smaller set of new keys, or artificially introduced key expiry).

We generate a new Ed25519-type key for use with `derivepassphrase`.

=== "UNIX (and Cygwin/MSYS, WSL, and Git for Windows)"

    We store the key as `my-vault-ed25519-key` in `~/.ssh`, using the comment "vault key".

    ~~~~ shell-session
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

=== "Windows"

    Start `puttygen`.
    Under "Parameters", as "Type of key to generate", select **EdDSA**, and as "Curve to use for generating this key", select **Ed25519 (256 bits)**.
    Then, under "Actions", select "Generate", and follow the on-screen instructions.
    Set the comment to "vault key", and set a strong key passphrase (*recommended*).
    Finally, select "Save private key", and store the key as `my-vault-ed25519-key.ppk` in `My Documents`.
    We can now close `puttygen`.

<section id="sample-key" markdown>

!!! note "Note: reproducibility"

    **SSH key generation is non-reproducible**: your key will naturally differ from ours, as will the key fingerprint, the randomart image (if any), and -- in general, for sufficiently loose constraints -- the passphrases derived from this master SSH key.
    This is *intentional* -- you wouldn't want others to be able to access all of your passphrases just because they installed the same software as you and have access to, or can guess, your configuration.

    This also means that you will get **different derived passphrases from us** unless you use [exactly the same master SSH key as we are using (OpenSSH format, no key passphrase)][TEST_KEY_OPENSSH] [(PuTTY format, no key passphrase)][TEST_KEY_PUTTY].[^test-key-comment]

[TEST_KEY_OPENSSH]: ../test_key_ed25519
[TEST_KEY_PUTTY]: ../test_key_ed25519.ppk

[^test-key-comment]:
    Technically, we are lying about the key comment you will be seeing when using our test key.

</section>

We then need to load the key into the agent, so that `derivepassphrase` can interact with it.
The key will persist as long as the agent is running, and will need to be re-added the next time the agent is started.

=== "UNIX (and Cygwin/MSYS, WSL, and Git for Windows)"

    We instruct the agent to pop up a confirmation prompt each time the key is used, as a safety precaution.

    ~~~~ shell-session
    $ ssh-add -c ~/.ssh/my-vault-ed25519-key
    Enter passphrase for .../.ssh/my-vault-ed25519-key (will confirm each use):
    Identity added: .../.ssh/my-vault-ed25519-key (vault key)
    The user must confirm each use of the key
    ~~~~

=== "Windows"

    Right-click on the `pageant` icon (the CRT computer monitor with the black hat) in the Windows task bar, then select "Add key (encrypted)".
    Select `my-vault-ed25519-key.ppk` in `My Documents`.
    The key should now be loaded.
    Double-click on the `pageant` icon, or right-click and then select "View keys", to bring up the list of keys `pageant` is currently holding in memory.
    The Ed25519 key we just created should be listed there, along with the "vault key" comment.

    Upon first use of the key, `pageant` will issue a passphrase prompt for the key passphrase.
    The key will be unlocked, and thus usable without prompts, until it is re-encrypted in the "View keys" menu.

## Reconfiguring the accounts

??? note "Reminder: interactive input"

    In code listings, sections enclosed in `[[...]]` signify input to the program, for you to type or paste in.

    Also, it is normal for passphrase prompts to not "echo" the text you type in.

In the previous tutorial that set up the three accounts, [we stored the settings for each account to `derivepassphrase vault`'s configuration](basic-setup-passphrase.md#summary), meaning that we only have to enter the master passphrase to access the account passphrases.

~~~~ shell-session
$ derivepassphrase vault --export -  # to confirm the configuration
{"services": {"email": {"length": 12, "repeat": 3, "lower": 1, "upper": 1, "number": 1, "space": 0}, "bank": {"length": 5, "lower": 0, "upper": 0, "number": 5, "space": 0, "dash": 0, "symbol": 0}, "work-2024Q4": {"length": 8, "upper": 1, "number": 1, "space": 0, "dash": 1, "symbol": 0}}}
~~~~

~~~~ shell-session
$ derivepassphrase vault -p email
Passphrase: [[I am an insecure master passphrase, but easy to type.]]
kEFwoD=C?@+7
$ derivepassphrase vault -p bank
Passphrase: [[I am an insecure master passphrase, but easy to type.]]
98517
$ derivepassphrase vault -p work-2024Q4
Passphrase: [[I am an insecure master passphrase, but easy to type.]]
-P268G0A
~~~~

We first reconfigure the `email` account to use the master SSH key.
`derivepassphrase` presents us with a key selector for all SSH keys suitable for passphrase derivation, including the one we generated earlier.

=== "Only one suitable key"

    We confirm the selection.

    ~~~~ shell-session
    $ derivepassphrase vault --config -k email
    Suitable SSH keys:
    [1] ssh-ed25519 ...gm1gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2  vault key
    Use this key? [[yes]]
    ~~~~

=== "Multiple suitable keys"

    We choose the correct key.

    ~~~~ shell-session
    $ derivepassphrase vault --config -k email
    Suitable SSH keys:
    [1] ssh-ed25519 ...gm1gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2  vault key
    [2] ssh-rsa ...YAWfeXycsvJZ2uaYRjMdZeJGNAnHLUGLkBscw5aI8=  some other key
    Your selection? (1-2, leave empty to abort): [[1]]
    ~~~~

We confirm that the reconfiguring has worked because the configuration for the `email` service now references the key we selected earlier.

~~~~ shell-session
$ derivepassphrase vault --export -
{"services": {"email": {"key": "AAAAC3NzaC1lZDI1NTE5AAAAIIF4gWgm1gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2", "length": 12, "repeat": 3, "lower": 1, "upper": 1, "number": 1, "space": 0}, "bank": {"length": 5, "lower": 0, "upper": 0, "number": 5, "space": 0, "dash": 0, "symbol": 0}, "work-2024Q4": {"length": 8, "upper": 1, "number": 1, "space": 0, "dash": 1, "symbol": 0}}}
~~~~

We further confirm that the derived passphrase adheres to the rules laid out for the `email` service.
Since we configured the service correctly, `derivepassphrase` knows to automatically use our previously selected SSH key.

~~~~ shell-session
$ derivepassphrase vault email
BNbSA\E]#s8H
~~~~

!!! note "Reminder: reproducibility"

    Unless you are using our SSH test key, **your SSH key will differ from ours, as will the derived passphrases**.

We can now log in to our email account with the old passphrase
(`derivepassphrase vault -p email`) and change it to the new one
(`derivepassphrase vault email`).

## Using the master SSH key by default

To get the other two services to use the master SSH key as well, we *could* reconfigure them manually, as we did with the `email` service.
However, that is unnecessarily repetitive.
Instead, we will set up `derivepassphrase` to use this master SSH key by default.

=== "Only one suitable key"

    ~~~~ shell-session
    $ derivepassphrase vault --config -k
    Suitable SSH keys:
    [1] ssh-ed25519 ...gm1gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2  vault key
    Use this key? [[yes]]
    ~~~~

=== "Multiple suitable keys"

    ~~~~ shell-session
    $ derivepassphrase vault --config -k
    Suitable SSH keys:
    [1] ssh-ed25519 ...gm1gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2  vault key
    [2] ssh-rsa ...YAWfeXycsvJZ2uaYRjMdZeJGNAnHLUGLkBscw5aI8=  some other key
    Your selection? (1-2, leave empty to abort): [[1]]
    ~~~~

The selected key will then appear in the `global` section of the configuration.

~~~~ shell-session
$ derivepassphrase vault --export -
{"global": {"key": "AAAAC3NzaC1lZDI1NTE5AAAAIIF4gWgm1gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2"}, "services": {"email": {"key": "AAAAC3NzaC1lZDI1NTE5AAAAIIF4gWgm1gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2", "length": 12, "repeat": 3, "lower": 1, "upper": 1, "number": 1, "space": 0}, "bank": {"length": 5, "lower": 0, "upper": 0, "number": 5, "space": 0, "dash": 0, "symbol": 0}, "work-2024Q4": {"length": 8, "upper": 1, "number": 1, "space": 0, "dash": 1, "symbol": 0}}}
~~~~

The `email` account still has an explicit configured SSH key, which overrides the global default setting; it just so happens that in this case both keys are the same.
We can therefore remove the useless key override from the `email` account.

~~~~ shell-session
$ derivepassphrase vault --config --unset=key email
$ derivepassphrase vault --export -
{"global": {"key": "AAAAC3NzaC1lZDI1NTE5AAAAIIF4gWgm1gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2"}, "services": {"email": {"length": 12, "repeat": 3, "lower": 1, "upper": 1, "number": 1, "space": 0}, "bank": {"length": 5, "lower": 0, "upper": 0, "number": 5, "space": 0, "dash": 0, "symbol": 0}, "work-2024Q4": {"length": 8, "upper": 1, "number": 1, "space": 0, "dash": 1, "symbol": 0}}}
~~~~

The generated passphrase is still the same.

~~~~ shell-session
$ derivepassphrase vault email
BNbSA\E]#s8H
~~~~

Finally, the generated passphrases for the `bank` and `work-2024Q4` accounts are affected by the global SSH key as well, as intended.

~~~~ shell-session
$ derivepassphrase vault bank
06041
$ derivepassphrase vault work-2024Q4
PE1qg_M7
~~~~

However, [the new passphrase for the `work` account does not yet adhere to the company's passphrase policy](basic-setup-passphrase.md#the-scenario) because [we are using the "wrong" special characters](basic-setup-passphrase.md#special-character).
We therefore change the passphrase generation parameters such that only dashes and no underscores are emitted.

~~~~ shell-session
$ derivepassphrase vault --config --lower=1 work-2024Q4
$ derivepassphrase vault work-2024Q4
pEY-qg7n
~~~~

We can then log into our bank and work accounts using the old passphrases (with `-p`) and change them to the new ones (without `-p`).

## Summary

We have reconfigured `derivepassphrase` (with the `vault` passphrase derivation scheme) for use with a master SSH key, and modified three existing accounts to use that key.
Our configuration should look like this:

~~~~ shell-session
$ derivepassphrase vault --export -
{"global": {"key": "AAAAC3NzaC1lZDI1NTE5AAAAIIF4gWgm1gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2"}, "services": {"bank": {"dash": 0, "length": 5, "lower": 0, "number": 5, "space": 0, "symbol": 0, "upper": 0}, "email": {"length": 12, "lower": 1, "number": 1, "repeat": 3, "space": 0, "upper": 1}, "work-2024Q4": {"dash": 1, "length": 8, "lower": 1, "number": 1, "space": 0, "symbol": 0, "upper": 1}}}
~~~~

We should also get the following output when asking for those passphrases again:

~~~~ shell-session
$ derivepassphrase vault email
BNbSA\E]#s8H
$ derivepassphrase vault bank
06041
$ derivepassphrase vault work-2024Q4
pEY-qg7n
~~~~

This completes the tutorial.

[BASIC_SETUP_PASSPHRASE]: basic-setup-passphrase.md
[PREREQ_SSH_KEY]: ../reference/prerequisites-ssh-key.md#ssh-key

[OPENSSH]: https://www.openssh.org/
[PUTTY]: https://putty.software/
