# `derivepassphrase` wish report-build-flags-and-features

???+ success "Wish details: `derivepassphrase` should report its build flags and supported features"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>wish</i><td>This is a request for an enhancement.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 0.2.0 0.3.0 0.3.1 0.3.2 0.3.3 <b>0.4.0</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/6741af2eaa6fba39717997292ec25baf5f1f4f20">6741af2eaa6fba39717997292ec25baf5f1f4f20</a> (0.5)
    </table>

Currently, `derivepassphrase` does not report its “build flags“ or its supported optional features (passphrase derivation schemes, PEP 508 extras, etc.). So callers of `derivepassphrase` need to infer support for optional features through other means, such as trying out the desired feature directly, or observing support indirectly e.g. in the `--help` output.

**Therefore**, `derivepassphrase` should include a way to report its build flags and supported features.

A common way to implement this is to expand the `--version` output to include this information (in a structured tabular format, for machine-parsability).

--------

This was implemented in commit 6741af2eaa6fba39717997292ec25baf5f1f4f20.
