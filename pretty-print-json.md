# `derivepassphrase` wish pretty-print-json

???+ success "Wish details: `derivepassphrase vault` should store and export the vault configuration in pretty-printed JSON"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>wish</i><td>This is a request for an enhancement.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 0.2.0 0.3.0 0.3.1 0.3.2 0.3.3 <b>0.4.0</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/b05668d5614d47158c8f8f0ef5145775d5ee40d8">b05668d5614d47158c8f8f0ef5145775d5ee40d8</a> (0.5)
    </table>

`derivepassphrase vault` stores and exports the vault configuration using the Python standard library's `json` module, with default settings.  This leads to very terse output in the configuration, particularly if it stores notes or SSH key references.  This terse notation, as reported to me by a certain non-Github user, becomes an unnecessary obstacle when debugging the configuration or looking up information in it.

I agree with this assessment when it comes to exports of the vault configuration, because this is an expression of the [transparency of the system](http://www.catb.org/~esr/writings/taoup/html/ch01s06.html#id2878054).  I do not agree for the *stored* vault configuration, which is a data file and which should not be touched by the user: that it uses the same JSON format as the export does is an implementation detail.  However, as a stopgap measure until better built-in configuration querying capabilities are available, this request is reasonable.

**Therefore**, pretty-print the vault configuration in both exports and in the stored configuration files.  The latter may be retired at a later date if replaced by better querying capabilities.
