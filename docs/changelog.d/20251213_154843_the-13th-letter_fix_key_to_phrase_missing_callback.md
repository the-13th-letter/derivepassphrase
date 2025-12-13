### Changed

  - For developers: The internal helper function
    `derivepassphrase._internals.cli_helpers.key_to_phrase` now takes
    mandatory callback parameters to handle warning and error messages.
    This is a side-effect of the "SSH agent socket providers" system, which
    necessitates more complicated error and warning handling.

    We considered making the callback parameters optional and supplying
    a default handler that suppress warnings and exit on error, but then we
    learned the hard way that those defaults make it too easy to suppress
    warnings *by accident*, just because we forgot to supply a certain
    function parameter.

