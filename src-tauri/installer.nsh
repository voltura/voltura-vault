; Tauri includes this file before defining its NSIS version.
!searchparse /file "${__FILEDIR__}\tauri.conf.json" '"version": "' VAULT_SETUP_VERSION '"'
Caption "$(^Name) ${VAULT_SETUP_VERSION} Setup"
