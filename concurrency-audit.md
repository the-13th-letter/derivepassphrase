# `derivepassphrase` bug concurrency-audit

???+ success "Bug details: Audit `derivepassphrase` for concurrency/thread-safety issues"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Priority<td><i>high</i><td>This should be fixed in the next release.
        <tr><th scope=col>Difficulty<td><i>tricky</i><td>Needs many tuits.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 0.2.0 0.3.0 0.3.1 0.3.2 0.3.3 <b>0.4.0</b>
        <tr><th scope=col>Fixed-in<td colspan=2>[a4ad05723414662d9df1607034c5dd7d646f1b49](https://github.com/the-13th-letter/derivepassphrase/commit/a4ad05723414662d9df1607034c5dd7d646f1b49) (0.5)
        <tr><th scope=col>Blocks<td colspan=2>[concurrency-testing-in-test-suite](concurrency-testing-in-test-suite.md)
    </table>

`derivepassphrase` is not explicitly written with concurrency in mind. This may come around to bite us when the “free-threaded“ build of Python no becomes a main feature.

Irrespective of that, it is a good idea anyway to have a clear picture on which parts of `derivepassphrase` are not threadsafe, and to which degree.

**Therefore**, audit `derivepassphrase` for concurrency/thread-safety issues.

--------

Off the top of my head, the main parts of `derivepassphrase` in the `export` and `vault` subcommands each construct their own data and only compute a result or read from the data, so there are no read-write or write-write dependencies.

The exceptions to this are the global logging and warnings handlers, which modify global state, and the `--config` option to `vault`, which writes back file contents.
