# Setting up `derivepassphrase vault` for three accounts, with a master passphrase

## The scenario

In this tutorial, we will setup `derivepassphrase` for three services, using a master passphrase and the standard `vault` passphrase derivation scheme.
We will assume the following three services with the following passphrase policies:

<div class="grid cards" markdown>

-   __email account__

    ---

    - between 12 and 20 characters
    - no spaces
    - 1 upper case letter, 1 lower case letter, 1 digit
    - no character may appear 3 times (or more) in a row

-   __bank account__

    ---

    - only digits
    - exactly 5 digits
    - an additional one-time password via a hardware token ("[two-factor authentication][2FA]")

-   __work account__

    ---

    - exactly 8 characters
    - no spaces
    - 1 special character, 1 letter, 1 digit
    - must be changed every quarter (January, April, July and October) to a different value ("passphrase rotation" or "rollover")
    - must actually be different from the previous *two* passphrases

</div>

[2FA]: https://en.wikipedia.org/wiki/Two-factor_authentication

## Installing `derivepassphrase`

You will need Python 3, and a package installer such as `pip` (bundled with Python), `pipx` or similar.

---

=== "pip"

    With `pip`, using a "virtual enviroment" at `~/.venv` to avoid clobbering our system configuration:

    ~~~~ shell-session
    $ python3 -m venv ~/.venv
    $ . ~/.venv/bin/activate
    $ pip install derivepassphrase
    ~~~~

=== "pipx"

    ~~~~ shell-session
    $ pipx install derivepassphrase
    ~~~~

---

Check that the installation was successful.

~~~~ shell-session
$ devirepassphrase --version
derivepassphrase, version 0.3.0
~~~~

(…or similar output.)

## Choosing a master passphrase

`derivepassphrase` uses a master passphrase <var>MP</var>, and derives all other passphrases <var>P</var> from <var>MP</var>.
We shall choose the master passphrase: `I am an insecure master passphrase, but easy to type.`

## Setting up the email account

In `derivepassphrase`, each passphrase configuration contains a *service name*, which is how `derivepassphrase` distinguishes between configurations.
This service name can be chosen freely, but the resulting passphrase depends on the chosen service name.
For our email account, we choose the straightforward service name `email`.

We need to translate the passphrase policy into options for `derivepassphrase`:

- A policy "(at least) <var>n</var> lower case letters" translates to the option <code>-<span/>-lower <var>n</var></code>, for any <var>n</var> > 0.
  Upper case letters (`--upper`), digits (`--number`), symbols (`--symbol`), spaces (`--space`) and dashes (`--dash`) work similarly.
- A policy "spaces *forbidden*" translates to the option `--space 0`.
  Again, other character classes behave similarly.
- A policy "no character may appear <var>n</var> times (or more) in a row" translates to the option <code>-<span/>-repeat (<var>n</var> − 1)</code>, for any <var>n</var> > 1.
  In particular, `--repeat 1` means no character may be immediately repeated.
  (See the mnemonic below.)
* A policy "between <var>n</var> and <var>m</var> characters long" translates to <code>-<span/>-length <var>k</var></code>, for any choice of <var>k</var> which satisfies <var>n</var> ≤ <var>k</var> ≤ <var>m</var>.
  (`derivepassphrase` does not explicitly choose <var>k</var> for you.)

??? info "Mnemonic: the `--repeat` option"

    The `--repeat` option denotes the *total* number of consecutive occurrences of the same character.
    Or alternatively: if you request <code>-<span/>-repeat <var>n</var></code>, then `derivepassphrase` will *avoid* deriving any passphrase that repeats a character *another <var>n</var> times*.

    Examples:

    | option        | valid examples         | invalid examples          |
    |:--------------|:-----------------------|:--------------------------|
    | `--repeat 1`  | `abc`, `aba`, `abcabc` | `aa`, `abba`, `ababb`     |
    | `--repeat 4`  | `122333111123`, `4444` | `55555`, `67788888999996` |
    | `--repeat 11` | `01234567899999999999` | `$$$$$$$$$$$$$$$$$$$$$$$` |


For the `email` service, we choose passphrase length 12.
This leads to the command-line options `--length 12 --space 0 --upper 1 --lower 1 --number 1 --repeat 3`.
Because we are using a master passphrase, we also need the `-p` option.

!!! note "Note: interactive input"

    In code listings, sections enclosed in `[[...]]` signify input to the program, for you to type or paste in.

    Also, it is normal for passphrase prompts to not "echo" the text you type in.

~~~~ shell-session
$ derivepassphrase vault --length 12 --space 0 --upper 1 --lower 1 \
>                        --number 1 --repeat 3 -p email
Passphrase: [[I am an insecure master passphrase, but easy to type.]]
kEFwoD=C?@+7
~~~~

By design, we can re-generate the same passphrase using the same input to `derivepassphrase`:

~~~~ shell-session
$ derivepassphrase vault --length 12 --space 0 --upper 1 --lower 1 \
>                        --number 1 --repeat 3 -p email
Passphrase: [[I am an insecure master passphrase, but easy to type.]]
kEFwoD=C?@+7
~~~~

We can then visit our email provider and change the passphrase to `kEFwoD=C?@+7`.

### Storing the settings to disk

Because it is tedious to memorize and type in the correct settings to re-generate this passphrase, `derivepassphrase` can optionally store these settings, using the `--config` option.

~~~~ shell-session
$ derivepassphrase vault --config --length 12 --space 0 --upper 1 --lower 1 \
>                        --number 1 --repeat 3 email
~~~~

!!! warning "Warning: `-p` and `--config`"

    Do **not** use the `-p` and the `--config` options together to store the master passphrase!
    The configuration is assumed to *not contain sensitive contents* and is *not encrypted*, so your master passphrase is then visible to *anyone* with appropriate privileges!

Check that the settings are stored correctly:

~~~~ shell-session
$ derivepassphrase vault --export -
{"services": {"email": {"length": 12, "repeat": 3, "lower": 1, "upper": 1, "number": 1, "space": 0}}}
~~~~

Once the settings are stored, only the service name and the master passphrase option are necessary:

~~~~ shell-session
$ derivepassphrase vault -p email
Passphrase: [[I am an insecure master passphrase, but easy to type.]]
kEFwoD=C?@+7
~~~~

## Setting up the bank account

We choose the straightforward service name `bank`.
The passphrase policy leads to the command-line options `--length 5 --lower 0 --upper 0 --number 5 --space 0 --dash 0 --symbol 0`.

The additional one-time password is generated by the hardware token, and therefore out of the scope for `derivepassphrase`.

The rest is similar to the `email` account: we configure our stored settings, generate the passphrase, and request the bank change the account passphrase to match the generated passphrase.

~~~~ shell-session
$ derivepassphrase vault --config --length 5 --lower 0 --upper 0 --number 5 \
>                        --space 0 --dash 0 --symbol 0 bank
$ derivepassphrase vault -p bank
Passphrase: [[I am an insecure master passphrase, but easy to type.]]
98517
~~~~

## Setting up the work account

We first take care of the first two constraints (passphrase length and permitted/required characters), then deal with the passphrase change/reuse aspects afterwards.
Again, we start with the straightforward service name `work`, we choose "upper case letters" to fulfill the "1 letter" requirement, and add the options `--length 8 --space 0 --symbol 1 --upper 1 --number 1`.

~~~~ shell-session
$ derivepassphrase vault --length 8 --space 0 --symbol 1 --upper 1 --number 1 \
>                        -p work
Passphrase: [[I am an insecure master passphrase, but easy to type.]]
r?9\XQR&
~~~~

Then we attempt to set the work passphrase to `r?9\XQR&`… but our employer's identity management system returns an error: `illegal character: &`.
What happened?

### Complication 1: What is a (permitted) "special character"?

`derivepassphrase` considers the characters `!"#$%&'()*+,./:;<=>?@[\]^{|}~-_'` to be permitted special characters.
Other service providers may permit other characters (quite rare) or fewer characters (quite common).
(Service providers may also *not* explicitly say which special characters they permit, except through trial and error.)

!!! abstract "Further reading"

    → How to deal with "supported" and "unsupported" special characters (TODO)

For this case specifically, we restrict ourselves to the dashes as the only permitted special characters, and hope that this passes their passphrase policy.

~~~~ shell-session
$ derivepassphrase vault --length 8 --space 0 --symbol 0 --dash 1 \
>                        --upper 1 --number 1 -p work
Passphrase: [[I am an insecure master passphrase, but easy to type.]]
it90-HPO
~~~~

This works.
For now.

### Complication 2: How to implement passphrase rotation?

`derivepassphrase` can only ever derive one passphrase per configuration, so passphrase rotation cannot be accomplished by reusing the same configuration.
So some part of the configuration---generally the service name---needs to change upon each rotation.

!!! abstract "Further reading"

    → How to deal with regular passphrase rotation (TODO)

We choose to append a very coarse timestamp to the "base" service name `work`: the 4-digit year, a `Q`, and the "quarter" number (1, 2, 3 or 4).
As of October 2024, this leads to the final service name `work-2024Q4`.

~~~~ shell-session
$ derivepassphrase vault --config --length 8 --space 0 --symbol 0 --dash 1 \
>                        --upper 1 --number 1 work-2024Q4
$ derivepassphrase vault -p work-2024Q4
Passphrase: [[I am an insecure master passphrase, but easy to type.]]
-P268G0A
~~~~

## Summary

We have installed `derivepassphrase` and set up three accounts for use with the `vault` passphrase derivation scheme, and the master passphrase `I am an insecure master passphrase, but easy to type.`.
Our configuration should look like this:

~~~~ shell-session
$ derivepassphrase vault --export -
{"services": {"email": {"length": 12, "repeat": 3, "lower": 1, "upper": 1, "number": 1, "space": 0}, "bank": {"length": 5, "lower": 0, "upper": 0, "number": 5, "space": 0, "dash": 0, "symbol": 0}, "work-2024Q4": {"length": 8, "upper": 1, "number": 1, "space": 0, "dash": 1, "symbol": 0}}}
~~~~

We should also get the following output when asking for those passphrases again:

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

This completes the tutorial.
