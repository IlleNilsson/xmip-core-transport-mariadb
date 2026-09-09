# Template setup

Complete this checklist before implementation.

**Item 3 is the one that gets skipped.** On 2026-08-26 eight repositories in the
estate were still called `xmip-template` — including two carrying more than
seven hundred lines of working code. Two crates with the same name cannot
coexist in one dependency graph, so nothing that depended on both could build,
and the cause was invisible because each repository compiled fine on its own.

1. Choose the final repository name and confirm that its boundary belongs in the
   Xmip architecture. Under ADR-0011 that is `xmip-<provider>-<module>`, or
   `xmip-<provider>-<module>-<standard>` where the module implements one.
2. Update the architecture specification and the architecture manifest together
   when the new repository changes the architecture baseline.
3. **Replace `xmip-template-rust` in `Cargo.toml`** — the package name, the
   description and the repository URL. The package name must equal the
   repository name.
4. Replace the template title and instructions in `README.md`.
5. Complete `ARCHITECTURE.md`: classification, maturity, owning capability,
   responsibility, public contracts, dependencies and non-responsibilities.
6. Keep the full AGPL-3.0 licence in `LICENSE` and `license =
   "AGPL-3.0-or-later"` in `Cargo.toml`.
7. Add verification that proves the repository's accepted responsibility and
   contracts.
8. Keep account-wide contribution, security, support, issue and pull-request
   defaults unless a reviewed repository-specific override is required.
9. Decide explicitly whether automatic verification triggers should be enabled.
   The template includes manual dispatch only.
10. Leave `rust-toolchain.toml` alone. It is the estate's toolchain, not this
    repository's preference.
11. Remove this setup file after every item is complete.

## Depending on another Xmip module

Pre-alpha convention, ADR-0005. Track `main` rather than pinning a commit:
pinning by revision across forty repositories needs two push rounds for every
change — push the code, let the gitlinks move, re-derive the revisions, push the
manifests again.

The package name is the repository name, and the dependency is aliased so the
import stays short:

```toml
xmip-context = { package = "xmip-core-context", git = "https://github.com/IlleNilsson/xmip-core-context", branch = "main" }
```

```rust
use xmip_context::MessageContext;
```

## This is a snapshot

Template repositories do not propagate. A change made here after a repository is
generated does not reach that repository, which is why `Sync-XmipEstate` checks
these invariants rather than trusting that the template established them.
