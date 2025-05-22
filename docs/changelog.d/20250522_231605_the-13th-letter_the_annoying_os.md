### Fixed

  - `derivepassphrase` has been successfully tested on <abbr
    title="Microsoft Windows">The Annoying OS</abbr>[^the-annoying-os] in
    its baseline version, i.e., without SSH agent functionality but with
    `cryptography` support.  All incompatibilities in the test suite were
    fixed if essential and/or feasible, or documented as skips or expected
    failures if neither.

    (The latter case currently only concerns one single test that is
    supposed to trigger OS errors while attempting to read the
    `derivepassphrase` configuration files. <abbr title="Microsoft
    Windows">The Annoying OS</abbr> happily returns an empty file instead.)

[^the-annoying-os]: Hat tip---and apologies---to
    [Timothée Mazzucotelli (`@pawamoy`)](https://github.com/pawamoy/) for
    the fitting terminology.
