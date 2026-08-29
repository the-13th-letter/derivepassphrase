### Fixed

  - For developers: In the test suite, correctly simulate that the
    `cryptography` library cannot be loaded, even if it is available.
    We no longer need separate virtual environments without `cryptography`
    installed to test `derivepassphrase`'s fallback behavior.
    This cuts the amount of test configurations (and thus test runtime) in
    half.
