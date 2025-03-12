# `derivepassphrase` wish scheme-specific-cli-and-config

???+ success "Wish details: Move `vault`-specific command-line interface into a separate CLI subcommand and matching configuration file"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>wish</i><td>This is a request for an enhancement.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 0.1.3 <b>0.2.0</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/69cf6a48483555dbcb4c8506673ef942fb008e18">69cf6a48483555dbcb4c8506673ef942fb008e18</a> (0.2.0)
        <tr><th scope=col>Blocks<td colspan=2>[other-derivation-schemes](other-derivation-schemes.md)
    </table>

In preparation for [other-derivation-schemes](other-derivation-schemes.md), move the current `vault`-specific command-line interface into a subcommand `vault`, and a matching configuration file `vault.json` instead of `config.json`.

Include machinery to automatically migrate to `vault.json`, with fallback to `config.json` if the former is not writable. (v1.0 will no longer support `config.json` or auto-migration.)
