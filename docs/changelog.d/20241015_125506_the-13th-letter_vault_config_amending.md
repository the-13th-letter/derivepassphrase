### Changed

  - In `derivepassphrase vault`, when importing configurations,
    correctly merge them with the existing one, same as vault(1): keep
    all named services and their settings (and the global settings if
    applicable) that are not mentioned in the imported configuration.
    The import procedure is thus more akin to a section-wise import of
    the configurations, instead of a "full" import, and the resulting
    configuration generally is a merge of both inputs.  ([#16])

[#16]: https://github.com/the-13th-letter/derivepassphrase/issues/16
