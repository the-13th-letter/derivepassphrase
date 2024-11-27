### Changed

  - Checking whether an SSH key is suitable now also depends on the SSH
    agent in use. API functions now optionally take an additional
    [`SSHAgentClient`][derivepassphrase.ssh_agent.SSHAgentClient] object to
    test agent-specific key suitability.
  - If the SSH agent supports deterministic DSA/ECDSA signatures (e.g.
    [RFC 6979][], then mark DSA and ECDSA SSH keys as suitable.

[RFC 6979]: https://www.rfc-editor.org/rfc/rfc6979
