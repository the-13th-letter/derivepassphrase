# How to deal with "supported" and "unsupported" special characters

Some services/websites impose a required minimum amount of "special characters" in their passphrases.
`derivepassphrase vault` considers the following characters as special characters: `!"#$%&'()*+,./:;<=>?@[\]^{|}~-_`.
However, in general, not every service/website will support this full range of special characters.
Worse, the service/website may not explicitly list the range of special characters it supports.

`derivepassphrase vault` supports restricting its range of special characters to `-_` via the `--dash` command-line option.
Beyond this, `derivepassphrase vault` does not support arbitrarily restricting its range of special characters -- you cannot directly tell `derivepassphrase` that a certain special character is "supported" or not.
Therefore, generating a passphrase acceptable to the service/website must be done indirectly, by finding a workable configuration.

Typically, a base configuration is "mutated" by changing the passphrase length, or requiring more or less fixed characters, until a workable configuration is found.

## Example

The work account from the [tutorial "Setting up `derivepassphrase vault` for three accounts, with a master passphrase"][BASIC_SETUP_PASSPHRASE] has the following stipulations: exactly 8 characters, no spaces, and 1 special character, 1 letter and 1 digit.
Per the tutorial, the first configuration was

~~~~ shell-session
$ derivepassphrase vault --length 8 --space 0 --symbol 1 --upper 1 --number 1 \
>                        -p work
Passphrase: [[I am an insecure master passphrase, but easy to type.]]
r?9\XQR&
~~~~

… which contained the unsupported special character `&`.
The stipulations forbid changing the length, but they do allow for the configured number of symbols, uppercase letters and digits to be mutated, and lowercase and uppercase letter counts to be exchanged.

Some example configurations that might turn out to be workable:

~~~~ shell-session
$ derivepassphrase vault --length 8 --space 0 --symbol 3 --upper 3 --number 2 \
>                        -p work
$ derivepassphrase vault --length 8 --space 0 --symbol 1 --upper 1 --number 6 \
>                        -p work
$ derivepassphrase vault --length 8 --space 0 --symbol 3 --lower 3 --number 2 \
>                        -p work
$ derivepassphrase vault --length 8 --space 0 --symbol 2 --upper 2 --lower 2 \
>                        --number 2 -p work
$ derivepassphrase vault --length 8 --space 0 --symbol 1 --upper 1 --lower 1 \
>                        --number 1 -p work
~~~~

For each such configuration, the user would check if the derived passphrase matches the supported set of special characters, and if so, use this configuration.

If all such configurations are enumerated without success, then the service name would need to be changed, and the process repeated.

[BASIC_SETUP_PASSPHRASE]: ../tutorials/basic-setup-passphrase.md
