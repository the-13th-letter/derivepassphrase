# `derivepassphrase` wish conventional-configurable-text-styling

???+ wish "Wish details: `derivepassphrase vault` should support conventional and configurable text styling"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>wish</i><td>This is a request for an enhancement.
        <tr><th scope=col>Priority<td><i>low</i><td>We aren&apos;t sure whether to fix this or not.
        <tr><th scope=col>Difficulty<td><i>taxing</i><td>Needs external things we don't have (standards, users etc).
        <tr><th scope=col>Requested-in<td colspan=2>0.5
    </table>

`derivepassphrase` intends to support text styling (color, boldface) for warning and error messages (and possibly for other future uses) for TTY devices.
**The question is, how exactly?
The conventions in this regard are still in flux.**

  * Color usage is generally tri-state: `--color=always|auto|never` (GNU `grep` et al.) or `--color=yes|no|auto` (pytest).
    Which terminology should be used?

  * For color usage, we should support the `NO_COLOR` and `FORCE_COLOR` environment variables to override the auto-detected result.
    Which variable should take precedence, `NO_COLOR` or `FORCE_COLOR`?
    (The `FORCE_COLOR` FAQ site gives `FORCE_COLOR` precedence over `NO_COLOR`, Python 3.13 gives `NO_COLOR` precedence.)

  * Should text decorations and text styling (bold, underline) be treated equivalently to color?
    Should this be handled by the same "color" options, or do we need separate "styling" options?

  * Should we support the [`TTY_COMPATIBLE=1|0|<unset>` variable as proposed by Rich](https://github.com/Textualize/rich/issues/2924#issuecomment-2757673602)?

* * *

<b>Therefore</b>, <em>once the conventions for requesting and disabling text styling on TTY devices have stabilized</em>, support the then-established conventions and mechanisms.
<b>Until then</b>, as a baseline, `derivepassphrase` shall emit device-independent output without color or text styling, in adherence to [Eric S. Raymond's Rule of Composition](http://www.catb.org/~esr/writings/taoup/html/ch01s06.html#id2877684).
(Baseline implemented in [64b076508d85bc24a28e253d081b4f2bf95b552c](https://git.schokokeks.org/derivepassphrase.git/commit/64b076508d85bc24a28e253d081b4f2bf95b552c).)
