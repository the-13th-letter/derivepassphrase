### Added

  - For `derivepassphrase vault`, support interacting with SSH agents on
    <abbr title="Microsoft Windows">The Annoying OS</abbr>, using Windows
    named pipes and the `SSH_AUTH_SOCK` environment variable.
    Also support the two major SSH agents Pageant ([PuTTY][]) and
    `ssh-agent` ([OpenSSH][]) specifically, without needing the user to
    specify the address of the Windows named pipe.
    [GnuPG][]'s `gpg-agent` (masquerading as OpenSSH's `ssh-agent`) is also
    known to work.

    This support is based on the [`ctypes.WinDLL`][ctypes.WinDLL] interface,
    and requires access to the `kernel32.dll` library on <abbr
    title="Microsoft Windows">The Annoying OS</abbr> at runtime.
    `derivepassphrase vault --version` will reliably report whether this
    feature -- the `windows_named_pipe`, `pageant_on_windows` and
    `openssh_on_windows` SSH agent socket providers -- is available.

    <b>Caveat</b>: On <abbr title="Microsoft Windows">The Annoying
    OS</abbr>, the user or developer should [mark all SSH agents as
    non-reentrant](#changed-in-v0.6-non-reentrant-ssh-agents) and run the
    test suite without parallelization, because the test suite cannot spawn
    isolated agents on <abbr title="Microsoft Windows">The Annoying
    OS</abbr>.
    The OpenSSH agent implementation interacts very badly with the feature
    detection logic from the test suite, because it shuts down the
    connection upon negative responses of any kind (in violation of the
    protocol); the user or developer may want to use GnuPG's emulation
    instead, or restrict themselves to PuTTY.
    →[:material-bug:][BUG_WINDOWS_SSH_AGENT_SUPPORT]

  - For `derivepassphrase vault`, support specifying the desired SSH agent
    socket provider via the command-line option
    `--ssh-agent-socket-provider` and via the configuration option
    `ssh-agent-socket-provider` in the `vault` table.
    The list of available providers can be queried with `derivepassphrase
    vault --version`.
    The command-line option takes precedence over the configuration option.

### Changed

  - For developers: The test suite now distinguishes between
    <dfn>isolated</dfn> SSH agents (spawned and managed by the test suite)
    and non-isolated ones (spawned by the user, potentially in use by other
    programs).

    All tests involving SSH agents are included in a separate group, so that
    the test harness distributes them to the same worker process.

  - For developers: The test suite now supports <b
    id="changed-in-v0.6-selective-ssh-agent-testing">selectively enabling
    SSH agents to test with</b> via the `PERMITTED_SSH_AGENTS` environment
    variable, which takes a comma-separated list of internal IDs of known
    SSH agent implementations.
    (Invalid entries are silently ignored.)
    The test suite will only attempt to spawn or interface with agents of
    permitted types, and skip tests otherwise.

    Intended to avoid spawning certain SSH agents just because they are
    installed, or spawning unrelated executables that are mistaken for
    the respective SSH agent due to identical executable names.

  - For developers: The test suite now supports <b
    id="changed-in-v0.6-non-reentrant-ssh-agents">marking SSH agents as
    non-reentrant</b> via the `NON_REENTRANT_SSH_AGENTS` environment
    variable, which takes a comma-separated list of internal IDs of known
    SSH agent implementations.
    (Invalid entries are silently ignored.)
    The test suite will avoid constructing multiple SSH agent clients
    connecting to such an SSH agent by reusing client instances, or skipping
    the test altogether.

    Intended to avoid deadlocks with shared agent instances that do not
    cleanly support multiple simultaneous clients.

      - [GnuPG][] v2.4.8 appears to use a single thread to both accept
        incoming SSH agent client connections and service them;
        running two clients simultaneously blocks the second client from
        connecting until the first client disconnects.
        This precludes normal usage in the test suite, where the test suite
        keeps a client connection to the agent open for the duration of the
        test run (to upload test keys at the beginning and remove them at
        the end).

      - Pageant principally supports multiple simultaneous clients.
        However, the test suite sporadically triggers errors where responses
        from Pageant contain extra blocks of NUL characters, confusing
        `derivepassphrase`.
        We have not observed any such errors yet when treating Pageant as
        non-reentrant.

        (So far, we have *only* been able to trigger these errors during
        test suite runs, not during instrumented calls specifically
        attempting to trigger this behavior.
        We are also unsure if this is a bug in Pageant, a bug in
        `derivepassphrase`, a bug or a limitation in Python's [`ctypes`][]
        implementation, or a bug or a limitation of Windows named pipes, or
        perhaps some combination of the aforementioned.)

[BUG_WINDOWS_SSH_AGENT_SUPPORT]: ../wishlist/windows-ssh-agent-support.md

[OpenSSH]: https://www.openssh.org
[PuTTY]: https://putty.software
[GnuPG]: https://gnupg.org
