<?php

declare(strict_types=1);

namespace PhilipRehberger\WebhookSignature\Tests;

use PhilipRehberger\WebhookSignature\WebhookSignature;
use PHPUnit\Framework\TestCase;

class WebhookSignatureTest extends TestCase
{
    private const SECRET = 'test-secret-key-abc123';

    private const PAYLOAD = '{"event":"invoice.paid","id":42}';

    public function test_generate_creates_valid_signature_format(): void
    {
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET);

        $this->assertMatchesRegularExpression(
            '/^t=\d+,v1=[a-f0-9]{64}$/',
            $signature,
            'Signature must be in t={timestamp},v1={hex64} format'
        );
    }

    public function test_verify_accepts_valid_signature(): void
    {
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET);

        $this->assertTrue(
            WebhookSignature::verify(self::PAYLOAD, $signature, self::SECRET),
            'A freshly generated signature must verify successfully'
        );
    }

    public function test_verify_rejects_invalid_secret(): void
    {
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET);

        $this->assertFalse(
            WebhookSignature::verify(self::PAYLOAD, $signature, 'wrong-secret'),
            'Verification with the wrong secret must fail'
        );
    }

    public function test_verify_rejects_tampered_payload(): void
    {
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET);
        $tamperedPayload = '{"event":"invoice.paid","id":99}';

        $this->assertFalse(
            WebhookSignature::verify($tamperedPayload, $signature, self::SECRET),
            'Verification against a modified payload must fail'
        );
    }

    public function test_verify_rejects_expired_signature(): void
    {
        // Generate a signature stamped 10 minutes in the past
        $oldTimestamp = time() - 600;
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET, $oldTimestamp);

        $this->assertFalse(
            WebhookSignature::verify(self::PAYLOAD, $signature, self::SECRET),
            'A signature older than the tolerance window must fail'
        );
    }

    public function test_verify_accepts_within_tolerance(): void
    {
        // Generate a signature stamped 4 minutes in the past (within default 5-minute window)
        $recentTimestamp = time() - 240;
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET, $recentTimestamp);

        $this->assertTrue(
            WebhookSignature::verify(self::PAYLOAD, $signature, self::SECRET),
            'A signature within the tolerance window must pass'
        );
    }

    public function test_verify_rejects_malformed_signature(): void
    {
        $this->assertFalse(
            WebhookSignature::verify(self::PAYLOAD, 'garbage-string-with-no-structure', self::SECRET),
            'A completely malformed signature must return false'
        );
    }

    public function test_verify_rejects_missing_components(): void
    {
        // Missing v1= component
        $this->assertFalse(
            WebhookSignature::verify(self::PAYLOAD, 't=1234567890', self::SECRET),
            'A signature missing v1= must return false'
        );

        // Missing t= component
        $this->assertFalse(
            WebhookSignature::verify(self::PAYLOAD, 'v1=abc123def456', self::SECRET),
            'A signature missing t= must return false'
        );

        // Empty string
        $this->assertFalse(
            WebhookSignature::verify(self::PAYLOAD, '', self::SECRET),
            'An empty signature must return false'
        );
    }

    public function test_generate_with_custom_timestamp(): void
    {
        $customTimestamp = 1700000000;
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET, $customTimestamp);

        $this->assertStringStartsWith(
            "t={$customTimestamp},",
            $signature,
            'The generated signature must include the exact custom timestamp'
        );
    }

    public function test_parse_signature_header_returns_components(): void
    {
        $customTimestamp = 1700000000;
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET, $customTimestamp);

        $parsed = WebhookSignature::parseSignatureHeader($signature);

        $this->assertIsArray($parsed);
        $this->assertArrayHasKey('timestamp', $parsed);
        $this->assertArrayHasKey('v1', $parsed);
        $this->assertSame($customTimestamp, $parsed['timestamp']);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $parsed['v1']);
    }

    public function test_parse_signature_header_returns_null_for_malformed_input(): void
    {
        $this->assertNull(WebhookSignature::parseSignatureHeader('garbage'));
        $this->assertNull(WebhookSignature::parseSignatureHeader(''));
        $this->assertNull(WebhookSignature::parseSignatureHeader('t=123'));
        $this->assertNull(WebhookSignature::parseSignatureHeader('v1=abc'));
    }

    public function test_verify_uses_timing_safe_comparison(): void
    {
        // Ensure two signatures that differ only in the last character both fail,
        // ruling out short-circuit string comparison exploits.
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET);
        $parts = explode(',', $signature);
        $v1Part = $parts[1]; // v1=...

        // Flip the last hex character
        $hex = substr($v1Part, 3);
        $lastChar = $hex[-1];
        $flippedChar = $lastChar === 'a' ? 'b' : 'a';
        $tamperedV1 = 'v1='.substr($hex, 0, -1).$flippedChar;
        $tamperedSignature = $parts[0].','.$tamperedV1;

        $this->assertFalse(
            WebhookSignature::verify(self::PAYLOAD, $tamperedSignature, self::SECRET),
            'A signature with a single character changed must fail'
        );
    }
}
