# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Governance standardization: `.gitattributes`, `.github/CODEOWNERS`, and `CHANGELOG.md`.

## [11.0.0] - 2026-11-26

### Added
- Global Auditable Holo `v11` Registry (`B8G_ABI_MAGIC_V3 = 0x33564742`) with `index/holo-compiler-lockfile.json` and Ed25519-signed `index/cas-v11-global-manifest.json`.
- Planetary Warm CAS deduplication (`v11/files/00..ff/<sha512>`), `68/68` upstream version pinning audit, and `CAS Q-Self` fixed-point verification (`bootstrap/selfhost-fixedpoint.mts`).
- Gravity Damper & Oversight telemetry (`reports/gravity-telemetry.json`, `reports/oversight-telemetry.json`) and `holo-ci@v1` verification.
