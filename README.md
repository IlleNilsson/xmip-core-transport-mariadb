# Xmip repository template — Rust

This repository is the starter snapshot for a Rust Xmip module repository. It is
not an Xmip runtime capability.

For a .NET 11 surface — the CLI, the PowerShell module, the MAUI desktop GUI or
the Blazor web GUI — use
[xmip-template-dotnet](https://github.com/IlleNilsson/xmip-template-dotnet)
instead. ADR-0014: every user-interfacing module is .NET 11, and
`xmip-core-abi` is the exception.

A repository generated from this template has independent history. Later
template changes do not automatically rewrite generated repositories.

## Before implementation

Follow [TEMPLATE_SETUP.md](TEMPLATE_SETUP.md), and item 3 first. The new
repository must be classified and declared in the authoritative Xmip
architecture manifest before its responsibility or dependencies are treated as
accepted architecture.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. rustup reads it
automatically and installs what is missing. Do not change it here — raising it
is one deliberate change across every repository.

## Shared governance

Repository-specific licensing remains explicit in [LICENSE](LICENSE).
Contribution, security, support, issue and pull-request defaults are inherited
from [IlleNilsson/.github](https://github.com/IlleNilsson/.github) when they are
not overridden locally.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`. It does not run on pushes, pull requests or a
schedule.

The ordered stages are formatting, semantic analysis, linting, compilation and
linking, and test execution. Packaging and publishing are not configured.
