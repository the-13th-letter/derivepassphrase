### Changed

  - For developers: The [SSH agent client][ssh_agent.SSHAgentClient] has
    separate internal methods for the "send" and the "receive" halves of
    a request, each of which can be stubbed individually.

  - For developers: Several internal and mostly-minor changes to the
    categorization and organization of the test suite should make it
    altogether faster to run if "correctness tests" are not desired, but
    fast feedback/"regression tests" are:

      - The `dev` and `intense` [hypothesis][] profiles are
        replaced by `regression`/`debug-regression` and `correctness`.
        The `flaky` profile has been dropped without replacement.
      - Some parametrized tests that should be property-based tests are now
        stubbed property-based tests.
        Likewise, some exhaustive property-based tests with only few inputs
        are now parametrized tests.
        There is explicit machinery for converting parametrized tests into
        stubbed property-based tests without too much writing effort.

    Other test suite improvements are not primarily based on the
    "correctness"/"regression" split, but nonetheless should make the test
    suite faster and/or easier to use:

      - SSH agent configurations and built-in SSH agent socket providers are
        now stored as an enum.
        SSH protocol numbers serialize as their byte representation.
      - A new "agent protocol response queue" class provides stub methods
        for the "send" and "receive" halves of an SSH agent request which
        map fixed request messages to fixed lists of response messages.
      - The stubbed SSH agent better mimics real-world agent communication
        channel behavior (incomplete requests, pipelined requests, channel
        shutdown).
      - SSH agent interaction tests run against the stubbed SSH agent or the
        agent protocol response queue where possible.
      - Some common functionality has been moved into `tests.data`,
        `tests.machinery` or `conftest`.

[hypothesis]: https://pypi.org/project/hypothesis/
