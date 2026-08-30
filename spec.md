# bug and wish entry specification

All bug and wish entries consist of a <dfn>header</dfn>, describing the properties of this entry, and a <dfn>summary</dfn> below.

The system is mostly compatible with PuTTY's wishlist; differences are marked below.
Unlike PuTTY, the entry files are not RFC822-like plain text, but rather Markdown files (with some raw HTML parts), to cleanly integrate with the rest of the documentation.
(The Markdown+HTML files are still very regular, and thus should still be reasonably parsable.)

## The header

The header is a table with fixed keys.
For some of the keys, if they have only a fixed amount of values they can take on, then they have a specific interpretation text that accompanies them.
In the order of appearance:

Summary
:   A brief description of the bug, in plain text.
    Comparable to subject lines in e-mail.

Class
:   What kind of entry is this?[^distinguishing-between-bugs-and-wishes]

    | value  | interpretation                                   |
    | ------ | ------------------------------------------------ |
    | `bug`  | This is clearly an actual problem we want fixed. |
    | `wish` | This is a request for an enhancement.            |

    (Unlike PuTTY, we do not further differentiate between `semi-bug`, `vulnerability` and `bug` at the class level.)

Priority
:   How urgent is this entry?
    An anchored ordinal scale with subjective interpretation.

    | value                              | interpretation                                                                |
    | ---------------------------------- | ----------------------------------------------------------------------------- |
    | `high`                             | This should be fixed in the next release.                                     |
    | `medium`                           | This should be fixed one day.                                                 |
    | `low`                              | We aren't sure whether to fix this or not.                                    |
    | `historic` (bug), `dormant` (wish) | This issue is old and we don't think it still has value on the main wishlist. |
    | `never`                            | We don't ever intend to fix this.                                             |

Difficulty
:   How difficult is this entry to fix/implement?
    An anchored ordinal scale with subjective interpretation.

    | value    | interpretation                                             |
    | -------- | ---------------------------------------------------------- |
    | `fun`    | Just needs tuits, and not many of them.                    |
    | `tricky` | Needs many tuits.                                          |
    | `taxing` | Needs external things we don't have (standards, users etc) |
    | `mayhem` | Probably impossible                                        |

Present-in:
:   For bugs only: A space-separated list of version numbers (for releases), dates or version control commit IDs (for snapshots) that the bug has been observed in.
    Dates are formatted as ISO 8601 `YYYY-MM-DD` dates, version numbers and commit IDs in their natural format without additional adornments.

    (PuTTY also factually uses <b>Present-in</b> for wishes.)

Absent-in:
:   For bugs only: A space-separated list of version numbers (for releases), dates or version control commit IDs (for snapshots) that the bug has been observed *not* in.
    Same formatting as for <b>Present-in</b>.

Requested-in:
:   For wishes only: A space-separated list of version numbers (for releases) or version control commit IDs (for snapshots), or a single date that the wish was requested in/on.

    (PuTTY uses <b>Present-in</b> for this purpose.)

Fixed-in:
:   A space-separated list of version numbers (for releases), dates or version control commit IDs (for snapshots) that the bug was fixed in or the wish was implemented in.
    Same formatting as for <b>Present-in</b>.
    Version control commit IDs may be prefixed with `~` to indicate that the bug/wish was confirmed fixed/implemented in this commit <i>or an ancestor commit</i>.

Depends:
:   A space-separated list of other bug/wish entry names that must be fixed/implemented first.

Blocks:
:   A space-separated list of other bug/wish entry names that are waiting for this entry to be fixed/implemented.

    (Not documented in PuTTY's wishlist entry specification, but in use across that wishlist.)

[^distinguishing-between-bugs-and-wishes]:
    A bug is specifically an entry describing an aspect of this software that, if not fixed, impedes or prohibits the user from accomplishing their goal with or within this software.
    Every other entry is a wish.

## The summary

The summary is a free-form prose summary of the bug or wish.
It is intended to be easily scannable, like a good commit message, and likely benefits from many of the same writing conventions.
In particular, the summary *should not* be a chronological listing of events or messages related to this bug or wish, but rather a proper summarization of those events, messages, and related facts and opinions.

Specific to this system, the summary always contains a paragraph beginning with <b>Therefore</b> that describes the action to take for this entry.
If applicable, a sentence beginning with <b>Until then</b> within that paragraph contains workarounds or partial solutions that will be applied or have already been applied.
Except for optional historical context that may follow this paragraph and is then hidden by default, the <b>Therefore</b> paragraph is the *last* paragraph of the summary.
