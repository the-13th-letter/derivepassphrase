# `derivepassphrase` wish export-vault-formats

???+ success "Wish details: Support data export from vault v0.2, vault v0.3, and storeroom storage formats"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>wish</i><td>This is a request for an enhancement.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 <b>0.1.2</b> 0.1.3
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/b4d8439fa4207b665ad8ea2217f21f807f603734">b4d8439fa4207b665ad8ea2217f21f807f603734</a> (0.2.0)
    </table>

Support extracting stored configurations from [vault][] v0.2, from v0.3, and from [storeroom][]-backed configurations.

v0.2 and v0.3 differ only in a technicality in how the encryption key for the stored data is derived. storeroom is a completely different design, but it is reasonably well documented in its readme.

  [vault]: https://github.com/jcoglan/vault 'jcoglan/vault'
  [storeroom]: https://www.npmjs.com/package/storeroom 'npm:storeroom'
