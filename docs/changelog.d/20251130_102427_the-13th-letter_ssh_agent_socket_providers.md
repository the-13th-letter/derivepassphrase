### Changed

  - The error message "Cannot connect to an SSH agent because this Python
    version does not support UNIX domain sockets." (code: `NO_AF_UNIX`) now
    reads "Cannot connect to an SSH agent because this Python version does
    not support communicating with it." and has a new code
    (`NO_AGENT_SUPPORT`).
    `derivepassphrase` may also try out certain communication channels
    (depending on the installation environment), and issue warnings relating
    to its failure to establish communication on those channels, before
    issuing the above error.

    The `NO_AF_UNIX` code is reused by the new warning message "Cannot
    connect to an SSH agent via UNIX domain sockets because this Python
    version does not support them.", which is one of the aforementioned
    related warning messages.

    The manpages document both the old and the new codes, with appropriate
    notices.

### Fixed

  - For developers: The manpage diagnostics helper scripts now explicitly
    support documentation of message codes that exist only as marks in the
    manpages, not in the program code.
    This allows documenting message codes that have since been removed from
    the program code.

