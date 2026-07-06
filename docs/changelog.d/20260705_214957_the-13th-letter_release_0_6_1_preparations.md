### Fixed

  - Work around a bug in the OpenSSH `ssh-agent` where a `query`
    request would receive a spurious
    [`SUCCESS`][derivepassphrase._types.SSH_AGENT.SUCCESS] response, so
    subsequent interactions (request-response pairs) would be misaligned.
    This only affects OpenSSH 10.3/10.3p1.
    →[:material-bug:][BUG_OPENSSH_BUG3967_WORKAROUND]

[BUG_OPENSSH_BUG3967_WORKAROUND]: wishlist/openssh-bug3967-workaround.md "Bug entry: “Work around faulty query response in OpenSSH 10.3”"

