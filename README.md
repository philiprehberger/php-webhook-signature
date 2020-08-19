# PHP Webhook Signature

[![Tests](https://github.com/philiprehberger/webhook-signature/actions/workflows/tests.yml/badge.svg)](https://github.com/philiprehberger/webhook-signature/actions/workflows/tests.yml)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/philiprehberger/php-webhook-signature.svg)](https://packagist.org/packages/philiprehberger/php-webhook-signature)
[![License](https://img.shields.io/github/license/philiprehberger/webhook-signature)](LICENSE)

Minimal, framework-agnostic HMAC-SHA256 webhook signature generation and verification with replay attack prevention.

## Requirements

| Dependency | Version |
|------------|---------|
| PHP        | ^8.2    |

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

## API

| Method | Description |
|--------|-------------|
| `WebhookSignature::generate(string $payload, string $secret, ?int $timestamp = null): string` | Sign a payload; returns the formatted `t={ts},v1={hmac}` header value |
| `WebhookSignature::verify(string $payload, string $signature, string $secret, int $tolerance = 300): bool` | Verify a signature; returns `false` if malformed, expired, or invalid |
| `WebhookSignature::verifyOrFail(string $payload, string $signature, string $secret, int $tolerance = 300): void` | Verify a signature; throws `InvalidSignatureException` or `SignatureExpiredException` on failure |
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
