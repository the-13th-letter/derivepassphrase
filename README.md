# derivepassphrase

[![PyPI - Version](https://img.shields.io/pypi/v/derivepassphrase.svg)](https://pypi.org/project/derivepassphrase)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/derivepassphrase.svg)](https://pypi.org/project/derivepassphrase)

An almost faithful Python reimplementation of [James Coglan's `vault`][VAULT], a deterministic password manager/generator.

Using a master passphrase or a master SSH key, derive a passphrase for a given named service, subject to length, character and character repetition constraints.

The derivation is *strong*: derived passphrases have as much entropy as permitted by the master passphrase and the passphrase constraints (whichever is more restrictive), and even if multiple derived passphrases are compromised, the master passphrase remains cryptographically difficult to discern from these compromised passphrases.
The derivation is also *deterministic*, given the same inputs, thus the resulting passphrase need not be stored explicitly.

The service name and constraints themselves also need not be kept secret; the latter are usually stored in a world-readable file to ease repeated entry of passphrase constraints.

[VAULT]: https://www.npmjs.com/package/vault

-----

## Installation

`derivepassphrase` is a pure Python package, and may be easily installed with any `pip`-compatible Python package manager such as `pip`, `pipx`, or `uv`.
(`pip` is distributed with Python 3 by default.)

`derivepassphrase` requires Python 3.9 or higher as well as the [typing-extensions package][TYPING_EXTENSIONS] for its core functionality and programmatic interface, and [`click`][CLICK] 8.1 or higher for its command-line interface.
On Python 3.9 and 3.10 only, `derivepassphrase` additionally requires the [tomli package][TOMLI].
The installer should take care of installing these dependencies automatically for you.
Using the `export vault` subcommand additionally requires the [cryptography package][CRYPTOGRAPHY], version 38.0 or newer.
This must be separately requested at installation, via the `export` extra.

<div class="grid cards" markdown>

  * **pipx**

    Use `pipx install derivepassphrase` in general, or `pipx install "derivepassphrase[export]"` with the `export` extra.

  * **uv**

    Use `uv tool install derivepassphrase` in general, or `uv tool install "derivepassphrase[export]"` with the `export` extra.

  * **pip**

    First, manually create a [virtual environment][VENV] and activate it.
    Then use `pip install derivepassphrase` in general, or `pip install "derivepassphrase[export]"` with the `export` extra.

</div>

`derivepassphrase` runs just fine on PyPy.
`derivepassphrase` *probably* also runs just fine on GraalPy, but this is untested.
(Feedback wanted!)

[TYPING_EXTENSIONS]: https://pypi.org/project/typing-extensions/
[CLICK]: https://pypi.org/project/click/
[TOMLI]: https://pypi.org/project/tomli/
[CRYPTOGRAPHY]: https://pypi.org/project/cryptography/
[VENV]: https://docs.python.org/3/library/venv.html

## Quick Usage

`derivepassphrase` is designed to principally support multiple passphrase derivation schemes, but currently only the "[vault][VAULT]" scheme is implemented.

Using the passphrase `This passphrase is for demonstration purposes only.` when prompted:

```` shell-session
$ derivepassphrase vault -p --length 30 --upper 3 --lower 1 --number 2 --space 0 --symbol 0 my-email-account
Passphrase: 
JKeet7GeBpxysOgdCEJo6UzmP8A0Ih
````

Some time later…

```` shell-session
$ derivepassphrase vault -p --length 30 --upper 3 --lower 1 --number 2 --space 0 --symbol 0 my-email-account
Passphrase: 
JKeet7GeBpxysOgdCEJo6UzmP8A0Ih
````

### Storing settings

`derivepassphrase` can store the length and character constraint settings in its configuration file so that you do not have to re-enter them each time.

```` shell-session
$ derivepassphrase vault --config --length 30 --upper 3 --lower 1 --number 2 --space 0 --symbol 0 my-email-account
$ derivepassphrase vault -p my-email-account
Passphrase: 
JKeet7GeBpxysOgdCEJo6UzmP8A0Ih
````

### SSH agent support

On UNIX-like systems with OpenSSH or PuTTY installed, you can use an Ed25519, Ed448 or RSA key from the agent instead of a master passphrase.
([On Windows there are problems establishing communication channels with the agent.][#13])

```` shell-session
$ derivepassphrase vault -k my-email-account
Suitable SSH keys:
[1] ssh-rsa ...feXycsvJZ2uaYRjMdZeJGNAnHLUGLkBscw5aI8=  test key without passphrase
[2] ssh-ed448 ...BQ72ZgtPMckdzabiz7JbM/b0JzcRzGLMsbwA=  test key without passphrase
[3] ssh-ed25519 ...gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2  test key without passphrase
Your selection? (1-3, leave empty to abort): 1
oXDGCvMhLWPQyCzYtaobOq2Wh9olYj
````

`derivepassphrase` can store the SSH key selection in its configuration file so you do not have to re-select it each time.
This choice can be made either specifically for the service (in this case, `my-email-account`), or globally.

```` shell-session
$ derivepassphrase vault --config -k  # global setting
Suitable SSH keys:
[1] ssh-rsa ...feXycsvJZ2uaYRjMdZeJGNAnHLUGLkBscw5aI8=  test key without passphrase
[2] ssh-ed448 ...BQ72ZgtPMckdzabiz7JbM/b0JzcRzGLMsbwA=  test key without passphrase
[3] ssh-ed25519 ...gJIXw//Mkhv5MEwidwcakUGCekJD/vCEml2  test key without passphrase
Your selection? (1-3, leave empty to abort): 1
$ derivepassphrase vault my-email-account
oXDGCvMhLWPQyCzYtaobOq2Wh9olYj
````

[#13]: https://github.com/the-13th-letter/derivepassphrase/issues/13 "Issue 13: Support PuTTY/Pageant (and maybe OpenSSH/ssh-agent) on Windows"

## License

`derivepassphrase` is distributed under the terms of the [zlib/libpng license](https://spdx.org/licenses/Zlib.html).
