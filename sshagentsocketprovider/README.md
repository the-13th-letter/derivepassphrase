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

To then actually register an SSH agent socket provider, build an `SSHAgentSocketProviderEntry` struct as follows:

~~~ python
def ssh_agent_over_stdin_stdout_provider() -> SSHAgentSocket: ...


stdin_stdout_entry_point = SSHAgentSocketProviderEntry(
    provider=ssh_agent_over_stdin_stdout_provider,
    key="stdin_stdout",
    aliases=("stdin", "stdout"),
)
~~~

Then add an appropriate entry point definition in your `pyproject.toml`, using the entry point group name `derivepassphrase.ssh_agent_socket_providers`:

~~~ toml
[project.entry."derivepassphrase.ssh_agent_socket_providers"]
first_provider = "mymodule: stdin_stdout_entry_point"
~~~

`derivepassphrase` will then pick up `stdin_stdout` as a new SSH agent socket provider, with aliases `stdin` and `stdout`.[^entry_point_name]

  [^entry_point_name]:
    Only the fields in `SSHAgentSocketProviderEntry` matter, not what names are used to declare the entry point.
    By convention, however, you would choose `stdin_stdout` as the entry point name, not `first_provider`.

## License

Like `derivepassphrase`, `derivepassphrase-sshagentsocketprovider` is distributed under the terms of the [zlib/libpng license](https://spdx.org/licenses/Zlib.html).
