# `derivepassphrase` bug fail-gracefully-without-af-unix

???+ bug-success "Bug details: Fail gracefully if support for UNIX domain sockets is unavailable"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 <b>0.2.0</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/ba27276a76a263a2d866bc55eca012f927c34877">ba27276a76a263a2d866bc55eca012f927c34877</a> (0.3.0)
    </table>

We generally support running `derivepassphrase` on systems where the SSH agent client is unusable because the system (or at least Python on that system) does not support UNIX domain sockets; see e.g. [windows-ssh-agent-support](windows-ssh-agent-support.md).  Currently, these fail with an `AttributeError` while resolving the `socket.AF_UNIX` symbol, instead of a more descriptive exception.

<b>Therefore</b>, correctly diagnose if the Python installation is lacking the `socket.AF_UNIX` symbol, and fail in an orderly manner.
