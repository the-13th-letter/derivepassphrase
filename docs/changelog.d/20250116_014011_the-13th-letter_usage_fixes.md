### Changed

  - `KeyCommentPair` from [`derivepassphrase._types`][], and `KeyPair` and
    `MasterKeys` from [`derivepassphrase.exporter.storeroom`][], have been
    converted to [`NamedTuple`s][typing.NamedTuple] and renamed to
    [`SSHKeyCommentPair`][derivepassphrase._types.SSHKeyCommentPair],
    [`StoreroomKeyPair`][derivepassphrase._types.StoreroomKeyPair] and
    [`StoreroomMasterKeys`][derivepassphrase._types.StoreroomMasterKeys],
    respectively, in the [`derivepassphrase._types`][] module.

    This is a **breaking API change**.
