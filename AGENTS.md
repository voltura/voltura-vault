# Voltura Vault

Use `main` as the primary branch. Use a short-lived feature branch and pull request for each future change. Merge verified work into `main` and delete the feature branch. Use `gh-pages` for the product site.

Treat preservation of existing vaults as an upgrade requirement. Preserve encrypted records, attachments, device profiles, pending edits and backup configuration. Test schema and format changes with an isolated existing vault and verify a recoverable backup before applying owner updates. Never reinitialize the live vault as part of an upgrade.

Keep owner deployment configuration, credentials, signing keys, vault data and recovery materials outside this repository. Use synthetic data and configuration for tests and CI. Run `npm run check`, `npm test` and `npm run build` after app changes. Run Rust tests when changing native or server code.
