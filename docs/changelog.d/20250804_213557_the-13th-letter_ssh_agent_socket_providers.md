### Added

  - For `derivepassphrase vault`, in the SSH agent client, introduce a new
    abstraction layer responsible for establishing the connection to the SSH
    agent: "SSH agent socket providers".
    Reframe the existing code for connecting to SSH agents on UNIX as
    a standard socket provider, and reserve a second standard socket
    provider, yet to be written, for <abbr title="Microsoft Windows">The
    Annoying Operating System</abbr>.

    (The system is based on Python package [entry
    points][importlib.metadata.entry_points], and is open for third-party
    developers to develop their own socket providers in case the standard
    socket providers are insufficient.)

  - `derivepassphrase vault --version` now defers testing for SSH agent
    support (the "master SSH key" feature) to the SSH agent client
    constructor, instead of examining the environment itself and drawing its
    own conclusions.

  - For developers: Feature flags and similar enum values are now
    self-testing, i.e., they include [their own code for testing whether they
    are active/enabled/supported][derivepassphrase._types.FeatureTestEnum].

