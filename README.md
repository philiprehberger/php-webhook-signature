# PHP Webhook Signature

[![Tests](https://github.com/philiprehberger/webhook-signature/actions/workflows/tests.yml/badge.svg)](https://github.com/philiprehberger/webhook-signature/actions/workflows/tests.yml)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/philiprehberger/php-webhook-signature.svg)](https://packagist.org/packages/philiprehberger/php-webhook-signature)
[![License](https://img.shields.io/github/license/philiprehberger/webhook-signature)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-GitHub%20Sponsors-ec6cb9)](https://github.com/sponsors/philiprehberger)

Minimal, framework-agnostic HMAC-SHA256 webhook signature generation and verification with replay attack prevention.

## Requirements

- PHP 8.2+

## Installation

```bash
composer require philiprehberger/php-webhook-signature
```

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

### Exception-Based Flow with `verifyOrFail()`

```php
use PhilipRehberger\WebhookSignature\WebhookSignature;
use PhilipRehberger\WebhookSignature\Exceptions\InvalidSignatureException;
use PhilipRehberger\WebhookSignature\Exceptions\SignatureExpiredException;

try {
    WebhookSignature::verifyOrFail($payload, $signature, $secret);
} catch (SignatureExpiredException $e) {
    http_response_code(401);
    exit('Signature expired');
} catch (InvalidSignatureException $e) {
    http_response_code(401);
    exit('Invalid signature');
}
```

### Key Rotation with Multiple Secrets

When rotating webhook secrets, both the old and new secrets can be accepted during the transition period:

```php
use PhilipRehberger\WebhookSignature\WebhookSignature;

$payload   = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] ?? '';

// Accept signatures signed with either the old or new secret
$secrets = [
    'new-secret-after-rotation',
    'old-secret-before-rotation',
];

if (! WebhookSignature::verifyWithMultipleSecrets($payload, $signature, $secrets)) {
    http_response_code(401);
    exit('Invalid signature');
}

// Signature matched one of the secrets — process the payload
$data = json_decode($payload, true);
```

### Algorithm-Specific Signing

Use `signWith()` and `verifyWith()` to sign and verify with SHA-384 or SHA-512 instead of the default SHA-256:

```php
use PhilipRehberger\WebhookSignature\SignatureAlgorithm;
use PhilipRehberger\WebhookSignature\WebhookSignature;

// Sign with SHA-512
$signature = WebhookSignature::signWith($payload, $secret, SignatureAlgorithm::Sha512);

// Verify with SHA-512
$valid = WebhookSignature::verifyWith($payload, $signature, $secret, SignatureAlgorithm::Sha512);
```

## API

| Method | Description |
|--------|-------------|
| `WebhookSignature::generate(string $payload, string $secret, ?int $timestamp = null): string` | Sign a payload; returns the formatted `t={ts},v1={hmac}` header value |
| `WebhookSignature::verify(string $payload, string $signature, string $secret, int $tolerance = 300): bool` | Verify a signature; returns `false` if malformed, expired, or invalid |
| `WebhookSignature::verifyOrFail(string $payload, string $signature, string $secret, int $tolerance = 300): void` | Verify a signature; throws `InvalidSignatureException` or `SignatureExpiredException` on failure |
| `WebhookSignature::signWith(string $payload, string $secret, SignatureAlgorithm $algorithm, ?int $timestamp = null): string` | Sign a payload using a specific algorithm (SHA-256, SHA-384, or SHA-512) |
| `WebhookSignature::verifyWith(string $payload, string $signature, string $secret, SignatureAlgorithm $algorithm, int $tolerance = 300): bool` | Verify a signature using a specific algorithm |
| `WebhookSignature::verifyWithMultipleSecrets(string $payload, string $signature, array $secrets, int $tolerance = 300): bool` | Verify against multiple secrets; returns `true` if any matches (key rotation) |
| `WebhookSignature::parseSignatureHeader(string $signature): ?array` | Parse a signature header into `['timestamp' => int, 'v1' => string]`; returns `null` on malformed input |

## Development

```bash
composer install
vendor/bin/phpunit
vendor/bin/pint --test
vendor/bin/phpstan analyse
```

## License

MIT
