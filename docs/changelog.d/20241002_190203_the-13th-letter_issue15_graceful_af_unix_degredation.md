### Changed

  - Fail earlier, and more gracefully/specifically, when we cannot talk to
    the SSH agent because Python does not support UNIX domain sockets on
    this system.  In particular, this is the current situation on Windows.

    This adds another failure case to the `SSHAgentClient` constructor, and
    therefore constitutes a breaking API change.

