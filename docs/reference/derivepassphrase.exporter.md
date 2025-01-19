::: derivepassphrase.exporter
    options:
      heading_level: 1

::: derivepassphrase.exporter.storeroom
    options:
      heading_level: 2

::: derivepassphrase.exporter.vault_native
    options:
      heading_level: 2
      filters:
        - "^[A-Za-z0-9]"
        - "^__[a-zA-Z0-9_-]+__"
        - "^_pbkdf2$"
        - "^_parse_contents$"
        - "^_derive_keys$"
        - "^_generate_keys$"
        - "^_check_signature$"
        - "^_hmac_input$"
        - "^_decrypt_payload$"
        - "^_make_decryptor$"
        - "^_evp_bytestokey_md5_one_iteration_no_salt$"
