# `derivepassphrase` bug print-service-notes

???+ bug-success "Bug details: `derivepassphrase vault` does not print service notes"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 0.2.0 0.3.0 0.3.1 0.3.2 0.3.3 <b>0.4.0</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/9b5805eb652e97ee4b63f6afbcf9563aba3311f0">9b5805eb652e97ee4b63f6afbcf9563aba3311f0</a> (0.5)
        <tr><th scope=col>Blocks<td colspan=2>[print-service-notes-above](print-service-notes-above.md){: .fixed }
    </table>

If vault(1) is asked to derive a passphrase for a service, and that service has associated notes, then vault(1) prints the notes (to standard error) after printing the derived passphrase.

`derivepassphrase vault` currently doesn't do this; it stores the notes, but doesn't otherwise access or act on them (apart from importing or exporting the configuration).

**Therefore**, make `derivepassphrase vault` also print the service notes when printing a derived passphrase.

This is an easy change on the technical side, but a somewhat tedious one concerning the documentation and the tests that need updating and/or rewriting.
