<?php

declare(strict_types=1);

namespace PhilipRehberger\WebhookSignature;

/**
 * Framework-agnostic HMAC-SHA256 webhook signature generation and verification
 * with replay attack prevention.
 *
 * Signature format: t={unix_timestamp},v1={hmac_sha256_hex}
 *
 * Usage by webhook receivers to validate incoming signed payloads.
 * Usage by webhook senders to sign outgoing payloads.
 */
class WebhookSignature
{
    /**
     * Verify a webhook signature.
     *
     * @param  string  $payload  The raw request body / JSON payload
     * @param  string  $signature  The X-Webhook-Signature header value
     * @param  string  $secret  The shared webhook secret
     * @param  int  $tolerance  Maximum age in seconds (default 5 minutes)
     */
    public static function verify(
        string $payload,
        string $signature,
        string $secret,
        int $tolerance = 300
    ): bool {
        $parts = self::parseSignature($signature);

        if (! $parts) {
            return false;
        }

        // Check timestamp tolerance to prevent replay attacks
        if (abs(time() - $parts['timestamp']) > $tolerance) {
            return false;
        }

        $expectedSignature = hash_hmac(
            'sha256',
            "{$parts['timestamp']}.{$payload}",
            $secret
        );

        return hash_equals($expectedSignature, $parts['v1']);
    }

    /**
     * Generate a signature header value for a payload.
     *
     * @param  string  $payload  The raw request body / JSON payload
     * @param  string  $secret  The shared webhook secret
     * @param  int|null  $timestamp  Unix timestamp to use; defaults to now
     * @return string Formatted as t={timestamp},v1={hmac}
     */
    public static function generate(string $payload, string $secret, ?int $timestamp = null): string
    {
        $timestamp = $timestamp ?? time();
        $signature = hash_hmac('sha256', "{$timestamp}.{$payload}", $secret);

        return "t={$timestamp},v1={$signature}";
    }

    /**
     * Parse a signature header into its timestamp and HMAC components.
     *
     * This is useful for inspecting the individual parts of a signature
     * without performing full verification.
     *
     * @param  string  $signature  The X-Webhook-Signature header value
     * @return array{timestamp: int, v1: string}|null Parsed components, or null if malformed
     */
    public static function parseSignatureHeader(string $signature): ?array
    {
        return self::parseSignature($signature);
    }

    /**
     * Parse the signature header into components.
     *
     * @return array{timestamp: int, v1: string}|null
     */
    private static function parseSignature(string $signature): ?array
    {
        $parts = [];

        foreach (explode(',', $signature) as $part) {
            if (! str_contains($part, '=')) {
                return null;
            }

            [$key, $value] = explode('=', $part, 2);
            $parts[$key] = $value;
        }

        if (! isset($parts['t']) || ! isset($parts['v1'])) {
            return null;
        }

        return [
            'timestamp' => (int) $parts['t'],
            'v1' => $parts['v1'],
        ];
    }
}
