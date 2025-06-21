# `derivepassphrase` bug concurrency-testing-in-test-suite

???+ bug-success "Bug details: Test for concurrency and assert thread-safety in `derivepassphrase`&apos;s test suite"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Priority<td><i>high</i><td>This should be fixed in the next release.
        <tr><th scope=col>Difficulty<td><i>tricky</i><td>Needs many tuits.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 0.2.0 0.3.0 0.3.1 0.3.2 0.3.3 <b>0.4.0</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/47376f4dcf2a2cc121df9b44b94b4036bf1bdb3b">47376f4dcf2a2cc121df9b44b94b4036bf1bdb3b</a> (0.5)
        <tr><th scope=col>Depends<td colspan=2>[concurrency-audit](concurrency-audit.md){: .fixed }
    </table>

Once [concurrency-audit](concurrency-audit.md) is resolved, the thread-safety of `derivepassphrase` should be explicitly asserted in the test suite.

**Therefore**, assert the thread-safety of `derivepassphrase` in the test suite.

--------

This was implemented in 47376f4dcf2a2cc121df9b44b94b4036bf1bdb3b.
