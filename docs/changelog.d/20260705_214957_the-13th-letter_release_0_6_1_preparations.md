### Fixed

  - Work around [OpenSSH bug 3967][OPENSSH_BZ3967] where a `query`
    request would receive a spurious [`SUCCESS`][_types.SSH_AGENT.SUCCESS]
    response, so subsequent interactions (request-response pairs) would be
    misaligned.
    This only affects OpenSSH 10.3/10.3p1.

[OPENSSH_BZ3967]: https://bugzilla.mindrot.org/show_bug.cgi?id=3967

