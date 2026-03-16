# philiprehberger/php-webhook-signature

[![Tests](https://github.com/philiprehberger/webhook-signature/actions/workflows/tests.yml/badge.svg)](https://github.com/philiprehberger/webhook-signature/actions/workflows/tests.yml)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/philiprehberger/webhook-signature.svg)](https://packagist.org/packages/philiprehberger/webhook-signature)
[![PHP Version Require](https://img.shields.io/packagist/php-v/philiprehberger/webhook-signature.svg)](https://packagist.org/packages/philiprehberger/webhook-signature)
[![License](https://img.shields.io/github/license/philiprehberger/webhook-signature)](LICENSE)

Minimal, framework-agnostic HMAC-SHA256 webhook signature generation and verification with replay attack prevention.

Works with Laravel, Symfony, plain PHP — any environment running PHP 8.2+.

## Installation

```bash
composer require philiprehberger/php-webhook-signature
```

## Signature Format

Every signed request carries a single header:

```
X-Webhook-Signature: t=1700000000,v1=a3f1...c9d2
```

| Component | Description |
|-----------|-------------|
| `t`       | Unix timestamp at the time of signing |
| `v1`      | HMAC-SHA256 hex digest of `{timestamp}.{payload}` |

The timestamp is included in the signed message so that altering it also invalidates the signature. On verification the timestamp is checked against a configurable tolerance window, which blocks replay attacks.

## Usage

### Sender Side — Signing an Outgoing Payload

```php
use PhilipRehberger\WebhookSignature\WebhookSignature;

$payload = json_encode(['event' => 'invoice.paid', 'id' => 42]);
$secret  = 'your-shared-webhook-secret';

$signatureHeader = WebhookSignature::generate($payload, $secret);
// "t=1700000000,v1=a3f1...c9d2"

// Attach to your outgoing HTTP request
$response = $httpClient->post($endpointUrl, [
    'headers' => [
        'Content-Type'        => 'application/json',
        'X-Webhook-Signature' => $signatureHeader,
    ],
    'body' => $payload,
]);
```

### Receiver Side — Verifying an Incoming Webhook

```php
use PhilipRehberger\WebhookSignature\WebhookSignature;

// Read the raw request body — do NOT decode it first
$payload   = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] ?? '';
$secret    = 'your-shared-webhook-secret';

if (! WebhookSignature::verify($payload, $signature, $secret)) {
    http_response_code(401);
    exit('Invalid signature');
}

// Signature is valid — process the payload
$data = json_decode($payload, true);
```

### Replay Attack Prevention

By default, signatures older than **300 seconds (5 minutes)** are rejected. Adjust the tolerance for your use case:

```php
// Accept signatures up to 60 seconds old
$valid = WebhookSignature::verify($payload, $signature, $secret, tolerance: 60);

// Disable replay protection entirely (not recommended)
$valid = WebhookSignature::verify($payload, $signature, $secret, tolerance: PHP_INT_MAX);
```

### Inspecting Signature Components

If you need to read the raw timestamp or HMAC before or without verifying:

```php
$parts = WebhookSignature::parseSignatureHeader($signatureHeader);

if ($parts !== null) {
    echo $parts['timestamp']; // int  — unix timestamp
    echo $parts['v1'];        // string — 64-character hex HMAC
}
```

Returns `null` if the header is malformed.

### Exception-Based Flow with `verifyOrFail()`

The simplest way to use exception-based flow is the `verifyOrFail()` method:

```php
use PhilipRehberger\WebhookSignature\WebhookSignature;
use PhilipRehberger\WebhookSignature\Exceptions\InvalidSignatureException;
use PhilipRehberger\WebhookSignature\Exceptions\SignatureExpiredException;

try {
    WebhookSignature::verifyOrFail($payload, $signature, $secret);
} catch (SignatureExpiredException $e) {
    // Signature was valid but too old — possible replay attack
    http_response_code(401);
    exit('Signature expired');
} catch (InvalidSignatureException $e) {
    // Signature was malformed or cryptographically invalid
    http_response_code(401);
    exit('Invalid signature');
}
```

### Manual Exception-Based Flow

The package also ships two exception classes for callers who prefer to wire exceptions into their own verification logic:

```php
use PhilipRehberger\WebhookSignature\WebhookSignature;
use PhilipRehberger\WebhookSignature\Exceptions\InvalidSignatureException;
use PhilipRehberger\WebhookSignature\Exceptions\SignatureExpiredException;

$parts = WebhookSignature::parseSignatureHeader($signature);

if ($parts === null) {
    throw new InvalidSignatureException('Malformed signature header.');
}

if (abs(time() - $parts['timestamp']) > 300) {
    throw new SignatureExpiredException();
}

if (! WebhookSignature::verify($payload, $signature, $secret)) {
    throw new InvalidSignatureException();
}
```

`SignatureExpiredException` extends `InvalidSignatureException`, which extends `\RuntimeException`, so you can catch at any level of granularity.

## API Reference

### `WebhookSignature::generate(string $payload, string $secret, ?int $timestamp = null): string`

Signs a payload. Returns the formatted `t={ts},v1={hmac}` header value. Pass a custom `$timestamp` in tests to produce deterministic output.

### `WebhookSignature::verify(string $payload, string $signature, string $secret, int $tolerance = 300): bool`

Verifies a signature. Returns `false` if the signature is malformed, expired, or cryptographically invalid. Uses `hash_equals()` for timing-safe comparison.

### `WebhookSignature::verifyOrFail(string $payload, string $signature, string $secret, int $tolerance = 300): void`

Verifies a signature and throws on failure. Throws `InvalidSignatureException` if the signature is malformed or cryptographically invalid. Throws `SignatureExpiredException` if the timestamp exceeds the tolerance window.

### `WebhookSignature::parseSignatureHeader(string $signature): ?array`

Parses a signature header into `['timestamp' => int, 'v1' => string]`. Returns `null` on malformed input.

> **Note:** `parseSignatureHeader()` now validates that the timestamp is numeric and that the v1 component is a valid 64-character hex string. Malformed values return `null`.

## Testing

```bash
composer install
vendor/bin/phpunit
```

## License

MIT License. See [LICENSE](LICENSE) for details.

