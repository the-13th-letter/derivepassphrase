# `derivepassphrase` bug windows-ssh-agent-support

???+ bug-success "Bug details: Support PuTTY/Pageant (and maybe OpenSSH/`ssh-agent`) on Windows"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Priority<td><i>high</i><td>This should be fixed in the next release.
        <tr><th scope=col>Difficulty<td><i>taxing</i><td>Needs external things we don't have: standards, users, et cetera.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 0.1.3 <b>0.2.0</b> 0.3.0 0.3.1 0.3.2 0.3.3 0.4.0 0.5 0.5.1 0.5.2
        <tr><th scope=col>Fixed-in<td colspan=2>[010e3e9c6c9d162d32d0fb2dd0bccbfd13747c42](https://git.schokokeks.org/derivepassphrase.git/010e3e9c6c9d162d32d0fb2dd0bccbfd13747c42)
    </table>

The SSH agent support in the default “vault” scheme originally assumed a UNIX host system, where all sensible SSH agent implementations use UNIX domain (`AF_UNIX`) sockets to connect the SSH client to the SSH agent, and expose the name of the socket in the `SSH_AUTH_SOCK` environment variable.

Windows historically did not support UNIX domain sockets. Portable programs using UNIX domain sockets usually resort to other inter-process communication designs when ported to Windows, e.g. a TCP/IP port on `localhost` plus an authentication token ([GnuPG 2.3](https://lists.gnupg.org/pipermail/gnupg-devel/2021-March/034795.html)), or Windows named pipes (PuTTY/Pageant, and OpenSSH-on-Windows).

Stock Python does not support connecting to Windows named pipes: this requires binding the `kernel32.dll` `CreateFileW` function, which Python does not readily provide.
As a result, while `derivepassphrase` does not actively use Windows-incompatible code for SSH agent handling, `derivepassphrase` cannot straightforwardly connect to the two main Windows SSH agent implementations.

<b>Therefore</b>, implement specific support on Windows to locate and connect to running Pageant or OpenSSH agent instances.

--------

??? info "Historical notes (September–October 2024)"

    Originally, we assumed that Pageant used a fixed address.  That turned out to be false: Pageant's named pipe address is a security capability, so it must be (computationally) unguessable.

    Originally, we assumed that OpenSSH for Windows used yet other means of advertising and of connecting to the running agent, [seemingly incompatible with the UNIX domain socket support in Windows 10 and later](https://github.com/PowerShell/Win32-OpenSSH/issues/1761).  That turned out to be false: OpenSSH for Windows uses named pipes with a fixed address, and the agent runs as a system service.

    --------

    <strong>Help wanted!</strong> As we have neither Windows experience nor Windows hardware to test this on, please get in touch if you can

    - confirm that `derivepassphrase` cannot talk to either SSH agent even if their (socket) address is stored in `SSH_AUTH_SOCK`,
    - provide help with implementing the necessary code to talk to Pageant/OpenSSH agent in their default configurations.

    --------

    As far as I can tell – still without having tried this out on actual Windows hardware – the current situation is as follows:

    1. [Microsoft implemented support for UNIX domain sockets, in certain constellations.][ANNOUNCEMENT] (Corrections: https://github.com/microsoft/WSL/issues/4240.)  Such support is available with some versions of Windows 10, and all versions of Windows 11.  There appears to be no further effort by Microsoft to provide further parts of the UNIX domain functionality (datagram sockets, abstract sockets, etc.)
    2. Because not all constellations are supported, Python does not support `socket.AF_UNIX` on Windows: https://github.com/python/cpython/issues/77589. There is a suggestion, but no consensus, to add a symbol `socket.WIN_AF_UNIX` or `socket.AF_UNIX_PARTIALSUPPORT` to officially expose whatever support Windows currently *does* have for UNIX domain sockets.
    3. PuTTY and OpenSSH for Windows predate such `AF_UNIX` support, and implement agent/client communication via Windows named pipes.  Windows named pipes are not compatible with the low-level UNIX I/O layer (`read`, `write`, etc.), and are not supported by the Python standard library in any form.  There appears to be no current PyPI package providing a useful interface to Windows named pipes—the pipes are not exposed as proper file objects or sockets, or they are not full duplex, or they cannot be explicitly named by the application.  This is usually because the implementation calls into the Windows kernel DLL directly, and wraps those specific functions necessary for the application to run; no attempt at providing a comprehensive and/or pythonic interface is made.
    4. PuTTY/Pageant uses [a default address for the named pipe, but that default address is *not constant*][PUTTY_PIPE_NAME]; it includes a personalized hash as a suffix.  This will be difficult to replicate in non-PuTTY code.  Accordingly, Pageant can be instructed to write out an OpenSSH-compatible config (the `IdentityAgent` line) for non-PuTTY clients, which we could then parse.
    5. OpenSSH for Windows offers the agent as a system-wide service.  There does not seem to be any support for spawning the agent outside of this system service context.  I do not know how the agent's socket address is communicated (if it is non-constant at all).
    6. Pageant on Windows *does* support exposing a UNIX domain stream socket, but because of (2), we cannot interact with it.  The support is limited to WSL 1; in WSL 2, UNIX domain sockets use a different namespace than Winsock sockets do, neither of which is accessible to the other.

    Given this situation, the most sensible thing to do is to give up on waiting for proper UNIX domain socket support in Windows/Python, and implement specific support for talking to an SSH agent via a Windows named pipe.  In particular, it also makes sense to correctly diagnose if the Python installation is lacking the `socket.AF_UNIX` symbol, and fail in an orderly manner.

[ANNOUNCEMENT]: https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
[PUTTY_PIPE_NAME]: https://git.tartarus.org/?p=simon/putty.git;a=blob;f=windows/utils/agent_named_pipe_name.c;h=aa64b3f60df455e06d6bc1b6c47923143b7a2dda;hb=a8601a72a918dfc2a8e8536a77139d7f37700044

--------

- July 2025: Now having access to a Windows machine, and a somewhat clearer understanding of how Python interfaces with external system libraries, start work on bringing support for Windows named pipes to `derivepassphrase`.

- August 2025: Introduce "SSH agent socket providers", an abstraction layer for (system-specific) code that constructs sockets connected to an SSH agent.

- November 2025: Finish work on SSH agent socket providers, particularly the restructuring of the test suite into "normal" and "heavy-duty" tests, the introduction of faked SSH agents (for testing purposes), and the parametrized testing of SSH agent interactions with all available SSH agent socket providers.

- December 2025: Implement the first successful connection from Python/[`ctypes`][] to Pageant and GnuPG on Windows.

- January 2026: Redo the test suite machinery *again*, because SSH agents on Windows are hard to isolate from each other, and the test suite is not prepared to deal with shared external resources just yet. Encounter lockups with GnuPG's OpenSSH emulation (consistently), and message corruption when talking to Pageant (very sporadically, only in the test suite but never in proof-of-concept scripts, and even when access to Pageant is protected by a lock).

- February 2026: Distinguish "non-reentrant" SSH agents from "reentrant" ones; the former cannot serve more than one client at once. This works around the lockups in GnuPG's OpenSSH emulation.

- February 2026: Support configuring the desired SSH agent socket provider in the configuration file and on the command-line. Update the manpages to reflect this.

- March 2026: Observe that when treating Pageant as non-reentrant, message corruption has not happened anymore.

- March 2026: Finish updating the documentation: a new tutorial, and new agent-specific notes for the "SSH key" how-to and reference page.
