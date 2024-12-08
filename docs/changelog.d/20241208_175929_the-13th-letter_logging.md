### Added

  - Both `derivepassphrase vault` and `derivepassphrase export vault` now
    support changing the amount of diagnostic output they emit via new
    command-line options `--debug`, `-v`/`--verbose` and `-q`/`--quiet`.
    Internally, this uses Python's standard [logging][] and [warnings][]
    systems.

### Changed

  - Calling [`derivepassphrase.cli.derivepassphrase_export`][],
    [`derivepassphrase.cli.derivepassphrase_export_vault`][] or
    [`derivepassphrase.cli.derivepassphrase_vault`][], or calling
    [`derivepassphrase.cli.derivepassphrase`][] via its
    [`.main`][click.BaseCommand.main] method, causes those functions to use
    the standard Python [logging][] and [warnings][] facilities to issue
    diagnostic messages, without output to standard error.  (This includes
    using [`click.testing.CliRunner`][], which uses `.main` calls under the
    hood.)  Calling [`derivepassphrase.cli.derivepassphrase`][] directly as
    a function diverts diagnostic messages to standard error.

