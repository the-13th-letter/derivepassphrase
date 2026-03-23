# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""The `derivepassphrase` test suite.

Overview
========

The `derivepassphrase` test suite contains testing support code and the
actual unit- and integration-test functions.

Layout (test functions)
=======================

`derivepassphrase` uses `pytest`, `coverage` and `hypothesis` for
testing.  Tests are auto-discovered using `pytest`'s test collection
machinery and configuration system, and may use `hypothesis` for
parametrization.

Layout (support code)
=====================

The testing support code is divided into five modules in two
subpackages: [`tests.data`][], [`tests.data.callables`][],
[`tests.machinery`][], [`tests.machinery.pytest`][] and
[`tests.machinery.hypothesis`][].  They have strict import requirements:
any module in this list may only import data and functionality from
modules earlier in this list.

  * The package [`tests.data`][] includes static test data, types, and
    associated lightweight machinery (think: accessors, categorization
    functions, and the like).

  * The module [`tests.data.callables`][] includes functions that
    operate on test data, or that alternatively implement stubbed
    versions of proper `derivepassphrase` functionality.  This includes
    test doubles, if they do not depend on the presence of certain test
    machinery.  Data is only included in this module (instead of in
    [`tests.data`][]) if it depends on the functions in this module.

  * The package [`tests.machinery`][] includes data and functions that
    is not specific to any test system, but which nonetheless is of
    little value outside of such a system.  This includes "fakes", i.e.
    reasonably complete reimplementations of existing `derivepassphrase`
    functionality, for comparison or "switching out" purposes.

  * The module [`tests.machinery.pytest`][] includes `pytest`-specific
    data and functions, such as marks and parametrization sets.

  * The module [`tests.machinery.hypothesis`][] includes
    `hypothesis`-specific data and functions, such as `hypothesis`
    strategies.

"""
