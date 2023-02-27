# Changelog

All notable changes to `webhook-signature` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-03-22

### Added
- `SignatureAlgorithm` enum with SHA-256, SHA-384, and SHA-512 support
- `signWith()` and `verifyWith()` methods for algorithm-specific signing and verification
- `verifyWithMultipleSecrets()` method for key rotation scenarios

## [1.1.4] - 2026-03-17

### Fixed
- Add phpstan.neon configuration for CI static analysis

## [1.1.3] - 2026-03-17

### Changed
- Standardized package metadata, README structure, and CI workflow per package guide

## [1.1.2] - 2026-03-16

### Changed
- Standardize composer.json: add type, homepage, scripts

## [1.1.1] - 2026-03-15

### Changed
- Add README badges

## [1.1.0] - 2026-03-12

### Added
- `WebhookSignature::verifyOrFail()` — verify or throw `InvalidSignatureException` / `SignatureExpiredException`
- `parseSignatureHeader()` now validates that `v1` is a 64-character hex string
- `parseSignatureHeader()` now validates that the timestamp is numeric

### Fixed
- Non-numeric timestamps (e.g. `t=abc`) are now rejected instead of silently cast to `0`
- Invalid `v1` values (non-hex, wrong length) are now rejected instead of accepted for comparison

## [1.0.0] - 2026-03-05

### Added
- `WebhookSignature::generate()` — sign an outgoing payload with HMAC-SHA256
- `WebhookSignature::verify()` — verify an incoming signature with replay attack prevention
- `WebhookSignature::parseSignatureHeader()` — inspect raw signature components
- `InvalidSignatureException` — thrown when signature verification fails
- `SignatureExpiredException` — thrown when the signature timestamp exceeds the tolerance window
- PHPUnit 11 test suite with full coverage of signing, verification, and edge cases
- GitHub Actions CI across PHP 8.2, 8.3, and 8.4
