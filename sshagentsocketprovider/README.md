# derivepassphrase-sshagentsocketprovider

[![PyPI - Version](https://img.shields.io/pypi/v/derivepassphrase-sshagentsocketprovider.svg)](https://pypi.org/project/derivepassphrase-sshagentsocketprovider)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/derivepassphrase-sshagentsocketprovider.svg)](https://pypi.org/project/derivepassphrase-sshagentsocketprovider)

An interface for SSH agent socket providers, which expose an abstract communication channel for an SSH agent to `derivepassphrase`.

This package contains only the interface definition and the types involved.

-----

## Installation

`derivepassphrase-sshagentsocketprovider` is a pure Python package, and may be easily installed with any `pip`-compatible Python package manager such as `pip`, `pipx`, or `uv`.
(`pip` is distributed with Python 3 by default.)

`derivepassphrase-sshagentsocketprovider` requires Python 3.9 or higher, as well as the [typing-extensions package][TYPING_EXTENSIONS].

```console
pip install derivepassphrase-sshagentsocketprovider
```

[TYPING_EXTENSIONS]: https://pypi.org/project/typing-extensions/

## Registering an SSH agent socket provider

The `SSHAgentSocket` represents the abstract communication channel to an SSH agent.
Ensure that the abstract channel behaves like a socket with respect to the `sendall` and `recv` operations.
The abstract channel must also be a context manager, which closes itself upon leaving the context, causing further `sendall` and `recv` operations to raise an error.
(By convention, this is `OSError`, with `errno.EBADF`.)

The `SSHAgentSocketProvider` is a callable that returns an `SSHAgentSocket` when called without arguments.

To then actually register an SSH agent socket provider, build an `SSHAgentSocketProviderEntry` struct.
For example:

~~~ python
# The class is an SSHAgentSocket and has an empty constructor, so the
# constructor is a valid SSHAgentSocketProvider.
class SSHAgentOverStdinStdoutSocket:
    """Forwarding STDIN/STDOUT, as if connected to an SSH agent."""

    FLAGS_ARE_UNSUPPORTED = "flags argument is unsupported"
    """Common error message."""

    def __enter__(self) -> Self:
        """Return self."""
        return self

    def __exit__(self, *args: object) -> bool | None:
        """Close stdin/stdout."""
        sys.stdin.close()
        sys.stdout.close()
        return None

    def send(self, data: Buffer, flags: int = 0, /) -> None:
        """Send data to agent."""
        if flags:
            raise ValueError(self.FLAGS_ARE_UNSUPPORTED)
        sys.stdout.buffer.write(data)

    def recv(self, bufsize: int, flags: int = 0, /) -> bytes:
        """Receive data from agent."""
        if flags:
            raise ValueError(self.FLAGS_ARE_UNSUPPORTED)
        return sys.stdin.buffer.read(bufsize)


ENTRY_POINT = SSHAgentSocketProviderEntry(
    provider=SSHAgentOverStdinStdoutSocket,
    key="stdin_stdout",
    aliases=("stdin", "stdout"),
)
~~~

Then add an appropriate entry point definition in your `pyproject.toml`, using the entry point group name `derivepassphrase.ssh_agent_socket_providers`:

~~~ toml
[project.entry."derivepassphrase.ssh_agent_socket_providers"]
first_provider = "mymodule: ENTRY_POINT"
~~~

`derivepassphrase` will then pick up `stdin_stdout` as a new SSH agent socket provider, with aliases `stdin` and `stdout`.[^entry_point_name]

  [^entry_point_name]:
    Only the fields in the `SSHAgentSocketProviderEntry` matter, not what names are used to declare the entry point.
    By convention, however, you would choose `stdin_stdout` as the entry point name, not `first_provider`.

(See the tests and the test data for two further examples.)

## License

Like `derivepassphrase`, `derivepassphrase-sshagentsocketprovider` is distributed under the terms of the [zlib/libpng license](https://spdx.org/licenses/Zlib.html).
