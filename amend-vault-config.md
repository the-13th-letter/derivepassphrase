# `derivepassphrase` bug amend-vault-config

???+ success "Bug details: `derivepassphrase vault --import` overwrites config instead of amending it"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 <b>0.2.0</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/7d6ac080e84b06a116063b3cfec9c40620242b94">7d6ac080e84b06a116063b3cfec9c40620242b94</a> (0.3.0)
    </table>

When importing a vault(1) configuration, `derivepassphrase` unconditionally overwrites the existing configuration with the imported one.

vault(1) however overwrites the existing configuration section-wise: each named service, and the global configuration if mentioned, is overwritten in whole by the respective imported settings.  This means that unmentioned named services (and perhaps the global section) are *inherited* from before the import.  (This should probably be called “merging” instead of “importing”.)

While I find `derivepassphrase`'s current import-without-merge behavior more intuitive than the import-with-merge behavior, vault(1) uses the latter.  <b>Therefore</b>, for compatibility with vault(1), implement the latter by default.
