<?php

declare(strict_types=1);

namespace PhilipRehberger\WebhookSignature\Tests;

use PhilipRehberger\WebhookSignature\Exceptions\InvalidSignatureException;
use PhilipRehberger\WebhookSignature\Exceptions\SignatureExpiredException;
use PhilipRehberger\WebhookSignature\SignatureAlgorithm;
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

    public function test_verify_or_fail_passes_for_valid_signature(): void
    {
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET);

        // Should not throw
        WebhookSignature::verifyOrFail(self::PAYLOAD, $signature, self::SECRET);

        $this->addToAssertionCount(1);
    }

    public function test_verify_or_fail_throws_invalid_signature_for_wrong_secret(): void
    {
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET);

        $this->expectException(InvalidSignatureException::class);

        WebhookSignature::verifyOrFail(self::PAYLOAD, $signature, 'wrong-secret');
    }

    public function test_verify_or_fail_throws_invalid_signature_for_malformed(): void
    {
        $this->expectException(InvalidSignatureException::class);

        WebhookSignature::verifyOrFail(self::PAYLOAD, 'garbage', self::SECRET);
    }

    public function test_verify_or_fail_throws_signature_expired_for_old_timestamp(): void
    {
        $oldTimestamp = time() - 600;
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET, $oldTimestamp);

        $this->expectException(SignatureExpiredException::class);

        WebhookSignature::verifyOrFail(self::PAYLOAD, $signature, self::SECRET);
    }

    public function test_verify_or_fail_uses_custom_tolerance(): void
    {
        $recentTimestamp = time() - 10;
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET, $recentTimestamp);

        // Should pass with 60s tolerance
        WebhookSignature::verifyOrFail(self::PAYLOAD, $signature, self::SECRET, 60);

        $this->addToAssertionCount(1);
    }

    public function test_verify_or_fail_throws_expired_at_exact_boundary(): void
    {
        $tolerance = 30;
        // Timestamp is exactly tolerance+1 seconds old
        $oldTimestamp = time() - ($tolerance + 1);
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET, $oldTimestamp);

        $this->expectException(SignatureExpiredException::class);

        WebhookSignature::verifyOrFail(self::PAYLOAD, $signature, self::SECRET, $tolerance);
    }

    public function test_parse_rejects_non_hex_v1(): void
    {
        // Construct a signature with non-hex v1
        $header = 't='.time().',v1=ZZZZ0000000000000000000000000000000000000000000000000000000000ZZ';

        $this->assertNull(WebhookSignature::parseSignatureHeader($header));
        $this->assertFalse(WebhookSignature::verify(self::PAYLOAD, $header, self::SECRET));
    }

    public function test_parse_rejects_short_v1(): void
    {
        $header = 't='.time().',v1=abcdef';

        $this->assertNull(WebhookSignature::parseSignatureHeader($header));
    }

    public function test_parse_rejects_non_numeric_timestamp(): void
    {
        $header = 't=not-a-number,v1='.str_repeat('a', 64);

        $this->assertNull(WebhookSignature::parseSignatureHeader($header));
        $this->assertFalse(WebhookSignature::verify(self::PAYLOAD, $header, self::SECRET));
    }

    public function test_parse_rejects_negative_timestamp(): void
    {
        $header = 't=-12345,v1='.str_repeat('a', 64);

        $this->assertNull(WebhookSignature::parseSignatureHeader($header));
    }

    public function test_verify_with_empty_payload(): void
    {
        $signature = WebhookSignature::generate('', self::SECRET);

        $this->assertTrue(WebhookSignature::verify('', $signature, self::SECRET));
    }

    public function test_verify_with_utf8_payload(): void
    {
        $utf8Payload = '{"name":"München","emoji":"🚀"}';
        $signature = WebhookSignature::generate($utf8Payload, self::SECRET);

        $this->assertTrue(WebhookSignature::verify($utf8Payload, $signature, self::SECRET));
    }

    public function test_exception_classes_are_instantiable(): void
    {
        $invalid = new InvalidSignatureException;
        $expired = new SignatureExpiredException;

        $this->assertInstanceOf(\RuntimeException::class, $invalid);
        $this->assertInstanceOf(InvalidSignatureException::class, $expired);
        $this->assertStringContainsString('verification failed', $invalid->getMessage());
        $this->assertStringContainsString('expired', $expired->getMessage());
    }

    public function test_exception_classes_accept_custom_messages(): void
    {
        $invalid = new InvalidSignatureException('Custom invalid message');
        $expired = new SignatureExpiredException('Custom expired message');

        $this->assertSame('Custom invalid message', $invalid->getMessage());
        $this->assertSame('Custom expired message', $expired->getMessage());
    }

    public function test_signature_algorithm_enum_values(): void
    {
        $this->assertSame('sha256', SignatureAlgorithm::Sha256->value);
        $this->assertSame('sha384', SignatureAlgorithm::Sha384->value);
        $this->assertSame('sha512', SignatureAlgorithm::Sha512->value);
    }

    public function test_signature_algorithm_hex_lengths(): void
    {
        $this->assertSame(64, SignatureAlgorithm::Sha256->hexLength());
        $this->assertSame(96, SignatureAlgorithm::Sha384->hexLength());
        $this->assertSame(128, SignatureAlgorithm::Sha512->hexLength());
    }

    public function test_sign_with_sha384_creates_valid_signature(): void
    {
        $signature = WebhookSignature::signWith(self::PAYLOAD, self::SECRET, SignatureAlgorithm::Sha384);

        $this->assertMatchesRegularExpression(
            '/^t=\d+,v1=[a-f0-9]{96}$/',
            $signature,
            'SHA-384 signature must have a 96-character hex HMAC'
        );
    }

    public function test_sign_with_sha512_creates_valid_signature(): void
    {
        $signature = WebhookSignature::signWith(self::PAYLOAD, self::SECRET, SignatureAlgorithm::Sha512);

        $this->assertMatchesRegularExpression(
            '/^t=\d+,v1=[a-f0-9]{128}$/',
            $signature,
            'SHA-512 signature must have a 128-character hex HMAC'
        );
    }

    public function test_verify_with_sha384_accepts_valid_signature(): void
    {
        $signature = WebhookSignature::signWith(self::PAYLOAD, self::SECRET, SignatureAlgorithm::Sha384);

        $this->assertTrue(
            WebhookSignature::verifyWith(self::PAYLOAD, $signature, self::SECRET, SignatureAlgorithm::Sha384),
            'A freshly generated SHA-384 signature must verify successfully'
        );
    }

    public function test_verify_with_sha512_accepts_valid_signature(): void
    {
        $signature = WebhookSignature::signWith(self::PAYLOAD, self::SECRET, SignatureAlgorithm::Sha512);

        $this->assertTrue(
            WebhookSignature::verifyWith(self::PAYLOAD, $signature, self::SECRET, SignatureAlgorithm::Sha512),
            'A freshly generated SHA-512 signature must verify successfully'
        );
    }

    public function test_verify_with_rejects_wrong_algorithm(): void
    {
        $signature = WebhookSignature::signWith(self::PAYLOAD, self::SECRET, SignatureAlgorithm::Sha384);

        $this->assertFalse(
            WebhookSignature::verifyWith(self::PAYLOAD, $signature, self::SECRET, SignatureAlgorithm::Sha512),
            'Verifying a SHA-384 signature with SHA-512 must fail'
        );
    }

    public function test_verify_with_rejects_wrong_secret(): void
    {
        $signature = WebhookSignature::signWith(self::PAYLOAD, self::SECRET, SignatureAlgorithm::Sha512);

        $this->assertFalse(
            WebhookSignature::verifyWith(self::PAYLOAD, $signature, 'wrong-secret', SignatureAlgorithm::Sha512),
            'Verification with the wrong secret must fail'
        );
    }

    public function test_sign_with_sha256_matches_generate(): void
    {
        $timestamp = 1700000000;
        $fromGenerate = WebhookSignature::generate(self::PAYLOAD, self::SECRET, $timestamp);
        $fromSignWith = WebhookSignature::signWith(self::PAYLOAD, self::SECRET, SignatureAlgorithm::Sha256, $timestamp);

        $this->assertSame(
            $fromGenerate,
            $fromSignWith,
            'signWith(SHA-256) must produce the same output as generate()'
        );
    }

    public function test_verify_with_multiple_secrets_matches_new_secret(): void
    {
        $oldSecret = 'old-secret-key';
        $newSecret = 'new-secret-key';
        $signature = WebhookSignature::generate(self::PAYLOAD, $newSecret);

        $this->assertTrue(
            WebhookSignature::verifyWithMultipleSecrets(self::PAYLOAD, $signature, [$oldSecret, $newSecret]),
            'Must verify when the new secret matches'
        );
    }

    public function test_verify_with_multiple_secrets_matches_old_secret(): void
    {
        $oldSecret = 'old-secret-key';
        $newSecret = 'new-secret-key';
        $signature = WebhookSignature::generate(self::PAYLOAD, $oldSecret);

        $this->assertTrue(
            WebhookSignature::verifyWithMultipleSecrets(self::PAYLOAD, $signature, [$oldSecret, $newSecret]),
            'Must verify when the old secret matches (key rotation)'
        );
    }

    public function test_verify_with_multiple_secrets_returns_false_when_no_secrets_match(): void
    {
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET);

        $this->assertFalse(
            WebhookSignature::verifyWithMultipleSecrets(self::PAYLOAD, $signature, ['wrong-1', 'wrong-2', 'wrong-3']),
            'Must return false when none of the provided secrets match'
        );
    }

    public function test_verify_with_multiple_secrets_returns_false_for_empty_array(): void
    {
        $signature = WebhookSignature::generate(self::PAYLOAD, self::SECRET);

        $this->assertFalse(
            WebhookSignature::verifyWithMultipleSecrets(self::PAYLOAD, $signature, []),
            'Must return false when no secrets are provided'
        );
    }
}
