# `derivepassphrase` bug test-filesystem-isolation

???+ success "Bug details: Isolate tests properly from the filesystem"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 <b>0.1.2</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/a980a643275de28f7715241790f199f947f637f4">a980a643275de28f7715241790f199f947f637f4</a> (0.1.3)
    </table>

Tests for the `derivepassphrase` command-line interface interact with the user's configuration, and will in general fail, unrelatedly, if said user configuration is broken.

While there *is* code to isolate the filesystem during tests, it is not yet consistently applied across all tests.

(Discovered while working on [configuration-directory-must-exist](configuration-directory-must-exist.md).)
