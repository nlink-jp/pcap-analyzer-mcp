# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Phase 1 (Planning): RFP in `docs/{en,ja}/`
- Phase 0 (Design): ADR-0001 through ADR-0007, `architecture`, `phase1-plan`
- Phase 2 (Scaffolding): repository structure, `Makefile`, `config.example.toml`,
  and the `serve` / `build-runtime` / `doctor` / `version` subcommand skeletons
- `internal/config`: config.toml loading with a single validation path
- Phase 1 Track B: MCP stdio protocol layer — `internal/transport`,
  `internal/jsonrpc`, `internal/mcpserver`, `internal/toolerr`

### Changed

- Release archives are 4 platforms, not 5: darwin ships arm64 only per
  CONVENTIONS.md §Release Archive Standard (effective 2026-07-12)
