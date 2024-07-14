# derivepassphrase

[![PyPI - Version](https://img.shields.io/pypi/v/derivepassphrase.svg)](https://pypi.org/project/derivepassphrase)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/derivepassphrase.svg)](https://pypi.org/project/derivepassphrase)

An almost faithful Python reimplementation of [James Coglan's `vault`][VAULT], a deterministic password manager/generator.

Using a master passphrase or a master SSH key, derive a passphrase for a given named service, subject to length, character and character repetition constraints.
The derivation is cryptographically strong, meaning that even if a single passphrase is compromised, guessing the master passphrase or a different service's passphrase is computationally infeasible.
The derivation is also deterministic, given the same inputs, thus the resulting passphrase need not be stored explicitly.
The service name and constraints themselves also need not be kept secret; the latter are usually stored in a world-readable file.

[VAULT]: https://getvau.lt

-----

## Installation

### With `pip`

```` shell-session
$ pip install derivepassphrase
````

### Manually

`derivepassphrase` is a pure Python package, and may be easily installed manually by placing the respective files and the package's dependencies into Python's import path.
`derivepassphrase` requires Python 3.10 or higher as well as the [typing-extensions package][TYPING_EXTENSIONS] for its core functionality and programmatic interface, and [`click`][CLICK] 8.1 or higher for its command-line interface.

[TYPING_EXTENSIONS]: https://pypi.org/project/typing-extensions/
[CLICK]: https://click.palletsprojects.com/

## Quick Usage

```` shell-session
$ derivepassphrase -p --length 30 --upper 3 --lower 1 --number 2 --space 0 --symbol 0 my-email-account
Passphrase: This passphrase is for demonstration purposes only.
JKeet7GeBpxysOgdCEJo6UzmP8A0Ih
````

Some time later…

```` shell-session
$ derivepassphrase -p --length 30 --upper 3 --lower 1 --number 2 --space 0 --symbol 0 my-email-account
Passphrase: This passphrase is for demonstration purposes only.
JKeet7GeBpxysOgdCEJo6UzmP8A0Ih
````

(The user input `This passphrase is for demonstration purposes only.` for the passphrase prompt is not actually displayed on-screen.)

## License

`derivepassphrase` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
