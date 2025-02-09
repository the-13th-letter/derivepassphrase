### Added

  - The `derivepassphrase` source tree now contains scripts to ensure
    consistent code quality: automatic linting, formatting and type
    checking, and optional running of the test suite and building of the
    documentation.  The master quality control script doubles as a
    servicable "pre-commit" hook for git.

### Fixed

  - Instead of having to do this by hand, `derivepassphrase` now includes
    build machinery to ensure consistency of its version number and its
    diagnostic messages between the documentation and the code.

    (The canonical way to get the version number is the
    [`importlib.metadata.version`][] standard library interface.)

