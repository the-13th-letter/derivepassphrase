# `derivepassphrase` bug no-stdlib-module-names

???+ bug-success "Bug details: Rename `types` submodules to `_types`"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 <b>0.1.2</b> 0.1.3
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/c4a57f311710768cb18df717a73fd48a8a3077fe">c4a57f311710768cb18df717a73fd48a8a3077fe</a> (0.2.0)
    </table>

It appears to be a *very* bad idea to name a submodule similar to a standard library module, as some tools, e.g. vim's keyword lookup (`K`), execute the code and then may run into "circular import" problems because the `types` submodule shadows the `types` standard library module.

So, rename the `types` submodules to `_types`.
