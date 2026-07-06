# `derivepassphrase` bug openssh-bug3967-workaround

???+ bug-success "Bug details: Work around faulty `query` response in OpenSSH 10.3"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2><b>0.6</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://git.schokokeks.org/derivepassphrase.git/commit/20bcd8f960b0655700905e9f20f807de15809188">20bcd8f960b0655700905e9f20f807de15809188</a>
    </table>

OpenSSH 10.3 is the first version to support the `query` extension request in its `ssh-agent`.
However, `ssh-agent` responds to each `query` extension request with *two* responses: once with the "normal" response, and once with a spurious empty `SUCCESS` response.
This causes all following requests to be misaligned, interpreting the wrong message as the intended response.

[The OpenSSH project acknowledges the bug][OPENSSH_BZ3967], and has a fix in preparation for 10.4.

We can detect and work around this situation by immediately issuing a subsequent `REQUEST_IDENTITIES` request, because it cannot legally have an empty `SUCCESS` response.
We then read the spurious empty `SUCCESS` response, if any, and the expected `IDENTITIES_ANSWER` or `FAILURE` response, and are then once again re-aligned.

<b>Therefore</b>, implement the above workaround to work seamlessly with OpenSSH 10.3.

[OPENSSH_BZ3967]: https://bugzilla.mindrot.org/show_bug.cgi?id=3967
