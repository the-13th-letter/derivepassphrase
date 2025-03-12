# `derivepassphrase` wish other-derivation-schemes

???+ question "Wish details: Consider implementing passphrase schemes other than vault&apos;s"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>wish</i><td>This is a request for an enhancement.
        <tr><th scope=col>Priority<td><i>low</i><td>We aren&apos;t sure whether to fix this or not.
        <tr><th scope=col>Difficulty<td><i>tricky</i><td>Needs many tuits.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 <b>0.1.2</b> 0.1.3 0.2.0 0.3.0 0.3.1 0.3.2 0.3.3 0.4.0
        <tr><th scope=col>Depends<td colspan=2>[scheme-specific-cli-and-config](scheme-specific-cli-and-config.md){: .fixed }
    </table>

Consider implementing other deterministic password/passphrase generation schemes, beyond vault.

Some candidates:

- [chriszarate/supergenpass](https://github.com/chriszarate/supergenpass)
- [grempe/strongpass](https://github.com/grempe/strongpass)
- [aprico-org/aprico-gen](https://github.com/aprico-org/aprico-gen)
- [Master Passphrase/Spectre.app scheme](https://spectre.app/blog/2018-01-06-algorithm/)

The hard part about these will probably not be the coding, but the correctness testing.
