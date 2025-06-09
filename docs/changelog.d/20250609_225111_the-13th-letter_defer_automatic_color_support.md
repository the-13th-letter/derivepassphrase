### Removed

  - `derivepassphrase` no longer supports (automatic) colored output or
    output with embedded text styling. There exist pseudo-standards (the
    `NO_COLOR` and `FORCE_COLOR` environment variables) governing how to
    influence this automatic detection, but they are under-specified with
    regard to their interaction with each other. Until a consensus is
    reached and automatic colored/styled output can be requested or rejected
    reliably across different terminal programs, `derivepassphrase` will
    rather emit only uncolored, unstyled, lowest-common-denominator
    device-independent output.

