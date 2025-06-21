# `derivepassphrase` bug falsy-vault-config-values

???+ bug-success "Bug details: `derivepassphrase vault` differs from vault(1) behavior with falsy stored configuration values"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 <b>0.2.0</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/7d2f2b1bda31ead428d3c009772aaf3d2261d60c">7d2f2b1bda31ead428d3c009772aaf3d2261d60c</a> (0.3.0)
    </table>

`derivepassphrase vault` uses a very strict validator to ensure that a configuration is valid, both its contents and its types.  For example, the configuration `{"global": {"phrase": null}, "services": {}}` is not valid according to `derivepassphrase`'s validator, because the `phrase` value must be a string.

vault(1) however tests most of its parameters for falsy values (in the JavaScript sense), and so will accept the configuration `{"global": {"phrase": null, "upper": ""}, "services": {}}`, among others.

<b>Therefore</b>, in the interest of compatibility with vault(1), convert all falsy values to their correctly typed equivalent before validating them.

We shall still make sure that any configuration we write is valid according to our validator as well, not just vault(1)'s.
