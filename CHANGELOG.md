# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-05

### Added
- `WebhookSignature::generate()` — sign an outgoing payload with HMAC-SHA256
- `WebhookSignature::verify()` — verify an incoming signature with replay attack prevention
- `WebhookSignature::parseSignatureHeader()` — inspect raw signature components
- `InvalidSignatureException` — thrown when signature verification fails
- `SignatureExpiredException` — thrown when the signature timestamp exceeds the tolerance window
- PHPUnit 11 test suite with full coverage of signing, verification, and edge cases
- GitHub Actions CI across PHP 8.2, 8.3, and 8.4
