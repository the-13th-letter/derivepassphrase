### Added

  - Add proper support for Buffer types in the SSH agent client.  Any
    Python object supporting the buffer protocol can be used as input to
    a function of the client, and any output from the client is returned
    as bytes objects.  Because of the zero-copy semantics of the
    underlying data/memory block, this should stay relatively time- and
    space-efficient.

### Fixed

  - Fixed the textual description of the return value for
    [`SSHAgentClient.request`]
    [derivepassphrase.ssh_agent.SSHAgentClient.request], which didn't
    match the declared type annotation.
