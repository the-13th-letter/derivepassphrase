# How to deal with regular passphrase rotation/rollover

`derivepassphrase vault` can only store one configuration per service name, and thus also generate only one passphrase per service name.
If a different passphrase is to be derived for a certain service *and* the previous derived passphrase(s) should remain accessible ("passphrase rotation"/"passphrase rollover"), we recommend using a set of *related service names* to designate the respective iterations of the service.

We recommend different choices of related service names, depending on whether the passphrase rotation is *regular* or *irregular*:

  - For regular passphrase rotation, we recommend appending a suffix to the service name that indicates the "period" for this iteration of the service (including the period length).

    For example, for monthly iteration, the service name would then be suffixed with the year and month, zero-filled: `-2025-06`, `:2024/09`, `@202603`, etc.
    For yearly iteration, the suffix would just contain the year: `-2025`, `:2024`, `@2026`.

    For quarterly iteration, the suffix would also contain a `Q` to indicate quarterly rotation: `-2025Q2`, `:2024Q3`, `@2026Q1`, etc.
    (Weekly and fortnightly rotation work similarly, with indicators `W` and `WW`, respectively, and with zero-filling.)

  - For irregular passphrase rotation (e.g. after a password reset), we recommend using a counter: `@3`, `:5`, `c12`, etc.

These recommendations ensure that the set of related service names sorts *naturally*, i.e., that the *last* entry is the *latest* entry.
