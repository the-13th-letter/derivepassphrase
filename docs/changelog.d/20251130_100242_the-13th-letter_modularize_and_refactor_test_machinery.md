### Fixed

  - Officially and systematically test on Python 3.14.

    Unofficial, non-systematic testing was already being done since v0.5.

  - For developers: Refactor the test suite into more fine-grained modules,
    and deduplicate code in the test methods in favor of parametrization.
    Both measures should make the test suite easier to navigate and less
    prone to copy-and-paste and code desynchronization mistakes.

