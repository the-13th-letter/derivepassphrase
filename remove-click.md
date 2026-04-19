# `derivepassphrase` wish remove-click

???+ bug "Wish details: Remove the dependency on `click`"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>wish</i><td>This is a request for an enhancement.
        <tr><th scope=col>Priority<td><i>high</i><td>This should be fixed in the next release.
        <tr><th scope=col>Difficulty<td><i>tricky</i><td>Needs many tuits.
        <tr><th scope=col>Requested-in<td colspan=2>0.5
    </table>

[`click`][click], the library which `derivepassphrase` uses to implement its command-line interface, used to have a very stable and essentially unchanging <abbr title="application programming interface">API</abbr> (up until v8.1.8) due to a maintenance bottleneck.
Several larger, backwards incompatible changes to `click` were in preparation, but withheld until the next major release.

In August 2025, a group of volunteers released [`click` v8.2.0][CLICK_V8_2_0], immediately implementing these withheld changes, without a deprecation period.
This caused both `derivepassphrase`'s command-line machinery and the test suite to immediately break because of changes in class hierarchies and function signatures.

The volunteers have since (March 2026) released multiple further versions, some of which include similar compatibility breaks without deprecation periods (e.g. [flag value handling in v8.3.0][CLICK_FLAG_HANDLING]).

This difference in library design philosophy is not reconcilable with `derivepassphrase`'s pledge to backwards compatibility.

`derivepassphrase` does not actually depend on functionality specific to `click`; any command-line creation library would principally do equally well.
`derivepassphrase` also needs to customize and reconfigure large parts of `click`'s infrastructure to better adhere to its use case -- UNIX-style command-line interfaces, in contrast to `click`'s <abbr title="operating system">OS</abbr>-native command-line interfaces.
The cost-benefit ratio of `click` v8.2.0+ is thus too high to justify its continued use.

<b>Therefore</b>, remove `click` as a dependency, and reimplement the command-line interface and testing machinery without it.
<b>Until then</b>, pin `click` to v8.1.8, the last version adhering to the <i lang=la>de facto</i> stable <abbr title="application programming interface">API</abbr>.

[click]: https://pypi.org/project/click/
[CLICK_V8_2_0]: https://click.palletsprojects.com/en/stable/changes/#version-8-2-0
[CLICK_FLAG_HANDLING]: https://click.palletsprojects.com/en/stable/changes/#version-8-3-0
