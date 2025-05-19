### Fixed

  - `derivepassphrase` now tests its locking implementation for correctness,
    on both sides of the API.  Specifically, we test that the respective
    platform-specific locking primitives provide the requested mutual
    exclusion properties, and we also test that the locking system as
    a whole, when given functioning locking primitives, correctly serializes
    access to the facilities it is supposed to guard.

[#23]: https://github.com/the-13th-letter/derivepassphrase/issues/23
