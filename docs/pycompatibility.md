# Compatibility of `derivepassphrase` with different Python versions

## Python 3.15  {#py3.15}

Supported as August 2026 without any known issues.

## Python 3.14  {#py3.14}

Supported as of v0.5.1 (June 2025) without any known issues.

### After end-of-life {#after-eol-py3.14}

After Python 3.14 reaches end-of-life, future `derivepassphrase` versions may make use of the following Python functionality:

  * lazy imports
  * the `frozendict` built-in type
  * the `sentinel` built-in type
  * unpacking in comprehensions
  * `bytearray.take_bytes(n=None, /)`

The declared minimum required Python version will then be updated accordingly.

## Python 3.13  {#py3.13}

Currently supported without any known issues.

### After end-of-life {#after-eol-py3.13}

After Python 3.13 reaches end-of-life, future `derivepassphrase` versions may make use of the following Python functionality:

  * template strings

The declared minimum required Python version will then be updated accordingly.

## Python 3.12  {#py3.12}

Currently supported without any known issues.

### After end-of-life {#after-eol-py3.12}

Python 3.13 does not offer significantly different functionality than Python 3.12.
There are thus no plans to make use of additional functionality once Python 3.12 reaches end-of-life.

## Python 3.11  {#py3.11}

Currently supported without any known issues.

### After end-of-life {#after-eol-py3.11}

After Python 3.11 reaches end-of-life, future `derivepassphrase` versions may make use of the following Python functionality:

  * complex expressions in f-strings
  * type parameter syntax and the `type` statement

The declared minimum required Python version will then be updated accordingly.

## Python 3.10  {#py3.10}

Currently supported without any known issues.

Some functionality requires backported libraries (`tomllib`/`tomli`).

### After end-of-life {#after-eol-py3.10}

After Python 3.10 reaches end-of-life, future `derivepassphrase` versions may make use of the following Python functionality:

  * exception groups
  * exception notes
  * [`contextlib.chdir`][]

The declared minimum required Python version will be then updated accordingly.

## Python 3.9  {#py3.9}

End-of-life since October 2025, but still supported at least until `derivepassphrase` v1.0, without any known issues.

Some functionality requires backported libraries (`tomllib`/`tomli`).

### After end-of-life {#after-eol-py3.9}

After Python 3.9 reaches end-of-life, future `derivepassphrase` versions may make use of the following Python functionality:

  * structural pattern matching (`match`/`case` blocks)
  * parenthesized `with` statements

The declared minimum required Python version will be then updated accordingly.

## Python 3.8 and below  {#py3.8-and-below}

These versions were never explicitly supported, neither in CPython nor in PyPy.
As of v0.6, Python 3.8 is known not to work due to standard library incompatibilities.

## PyPy

As per the respective CPython version above.
