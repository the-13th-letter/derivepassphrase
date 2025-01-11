### Changed

  - The [export handler for storeroom][derivepassphrase.exporter.storeroom.export_storeroom_data] and for [vault-native][derivepassphrase.exporter.vault_native.export_vault_native_data] configuration data now [both support a unified interface][derivepassphrase.exporter.ExportVaultConfigDataFunction].
    A new dispatch function [`export_vault_config_data`][derivepassphrase.exporter.export_vault_config_data] automatically calls the correct backend, based on the requested format.

    This is a **breaking API change** due to the change in function parameter names and return types.
