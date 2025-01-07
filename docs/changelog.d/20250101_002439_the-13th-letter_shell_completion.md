### Added

  - `derivepassphrase` now explicitly supports shell completion, in
    particular filename and service name completion in the `export vault`
    and `vault` subcommands.

    However, because of restrictions regarding the exchange of data between
    `derivepassphrase` and the shell, `derivepassphrase` will not offer any
    service names containing ASCII control characters for completion, and
    a warning will be issued when importing or configuring such a service.
    They may still otherwise be used normally.
