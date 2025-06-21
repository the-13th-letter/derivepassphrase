# `derivepassphrase` wish print-service-notes-above

???+ wish-success "Wish details: `derivepassphrase vault` should be able to print service notes *above* the passphrase"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>wish</i><td>This is a request for an enhancement.
        <tr><th scope=col>Present-in<td colspan=2><b>0.4.0</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/9b5805eb652e97ee4b63f6afbcf9563aba3311f0">9b5805eb652e97ee4b63f6afbcf9563aba3311f0</a> (0.5)
        <tr><th scope=col>Depends<td colspan=2>[print-service-notes](print-service-notes.md){: .fixed }
    </table>

See [print-service-notes](print-service-notes.md) for context.

vault(1) always prints the derived service passphrase first, and the notes (if any) second.  This is sometimes weird to read if the notes contain explanation or supplementary info concerning the passphrase.

`derivepassphrase vault` should support printing the notes before the passphrase as well, not just after.

**Therefore**, add support for printing the notes before the passphrase.
