# `derivepassphrase` bug single-toplevel-module

???+ bug-success "Bug details: Move `sequin` and `ssh_agent_client` modules into `derivepassphrase` package"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 <b>0.1.2</b> 0.1.3
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/c4a57f311710768cb18df717a73fd48a8a3077fe">c4a57f311710768cb18df717a73fd48a8a3077fe</a> (0.2.0)
    </table>

The current layout, using three top-level Python packages `derivepassphrase`, `sequin` and `ssh_agent_client`, is error-prone:

- The `sequin` module and the `ssh_agent_client` package already are tightly coupled to the `derivepassphrase` package, insofar as their scope and functionality is solely dictated by the `derivepassphrase` package. `sequin` in particular is *very* special purpose, and unlikely to be useful in contexts other than passphrase generation.
- For 0.1.0 and 0.1.1, the Python wheels forgot to include `sequin` and `ssh_agent_client`, which led to broken installations.
- Version info via the `__version__` attribute needs to be replicated across all three top-level packages.
- At least `ssh_agent_client` is likely enough a module/package name that we may expect name collisions in the future.

Since the only argument I have for keeping the packages separate is decoupling and independent evolution, which I think is completely mitigated by the <i lang="la">de facto</i> coupling to the `derivepassphrase` package anyway, I wish to integrate the `sequin` module and the `ssh_agent_client` package into the `derivepassphrase` package in the long run (and perhaps consolidate both `types` submodules).
