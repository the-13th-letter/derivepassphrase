# `derivepassphrase` wish no-strict-compatibility-mode

???+ wish "Wish details: Provide a mode of operation forfeiting strict compatibility"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>wish</i><td>This is a request for an enhancement.
        <tr><th scope=col>Priority<td><i>medium</i><td>This should be fixed one day.
        <tr><th scope=col>Difficulty<td><i>fun</i><td>Just needs tuits, and not many of them.
        <tr><th scope=col>Requested-in<td colspan=2>0.5.2
    </table>

`derivepassphrase vault` contains multiple options (e.g., `--modern-editor-interface`) that change its behavior in a manner incompatible with <i>vault</i>(1), but which the user may nevertheless want to select because the <i>vault</i>(1) behavior is surprising, inconsistent, etc.

Because of our commitment to backwards compatibility with <i>vault</i>(1), such divergent behavior must be requested separately for each call to `derivepassphrase`.
Currently, this means manually adding the respective options to each command-line invocation.

Alternatively, we could add configuration settings corresponding to those behavior-changing options, and provide a single option (e.g., `--no-strict-compatibility`) that instructs `derivepassphrase` to honor those configuration settings, even if the resulting behavior differs from <i>vault</i>(1).
This alleviates the cognitive load on the user -- they only need to remember the `--no-strict-compatibility` options, not their specific collection of behavior change options.
It is also easily extendable to other passphrase derivation schemes and their original implementations.

<b>Therefore</b>, implement a common option to turn off strict command-line compatibility with <i>vault</i>(1) (and other original implementations of passphrase derivation schemes) and to honor behavioral change settings specified in the configuration.
