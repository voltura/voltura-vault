# Voltura Vault

Use `main` as the primary branch. Use a short-lived feature branch and pull request for each future change. Merge verified work into `main` and delete the feature branch. Use `gh-pages` for the product site.

Preserve encrypted records, attachments, device profiles, pending edits and backup configuration during upgrades. Test schema and format changes with an isolated vault.

Keep deployment credentials, signing keys, vault data and recovery materials outside this repository. Use synthetic data and configuration for tests and CI. Run `npm run check`, `npm test` and `npm run build` after app changes. Run Rust tests when changing native or server code.
