# Compatibility of `derivepassphrase` with different Python versions

## Python 3.14  {#py3.14}

Not yet supported.
As of 2025-01, Python 3.14 is still in alpha stage.

## Python 3.13  {#py3.13}

Currently supported without any known issues.

## Python 3.12  {#py3.12}

Currently supported without any known issues.

## Python 3.11  {#py3.11}

Currently supported without any known issues.

### After end-of-life {#after-eol-py3.11}

After Python 3.11 reaches end-of-life, future `derivepassphrase` versions may make use of the following Python functionality:

  * complex expressions in f-strings
  * type parameter syntax and the `type` statement

## Python 3.10  {#py3.10}

Currently supported without any known issues.

Some functionality requires backported libraries (`tomllib`/`tomli`).

### After end-of-life {#after-eol-py3.10}

After Python 3.10 reaches end-of-life, future `derivepassphrase` versions may make use of the following Python functionality:

  * exception groups
  * exception notes
  * [`contextlib.chdir`][]

## Python 3.9  {#py3.9}

Currently supported without any known issues.

Some functionality requires backported libraries (`tomllib`/`tomli`).

### After end-of-life {#after-eol-py3.9}

After Python 3.9 reaches end-of-life, future `derivepassphrase` versions may make use of the following Python functionality:

  * structural pattern matching (`match`/`case` blocks)
  * parenthesized `with` statements

## Python 3.8 and below  {#py3.8-and-below}

These versions were never explicitly supported, neither in CPython nor in PyPy.
The same versions as for [Python 3.9](#py3.9) may work, but this is untested.

## PyPy

As per the respective CPython version above.
