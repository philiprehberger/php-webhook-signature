<?php

declare(strict_types=1);

namespace PhilipRehberger\WebhookSignature;

/**
 * Supported HMAC algorithms for webhook signature generation and verification.
 */
enum SignatureAlgorithm: string
{
    case Sha256 = 'sha256';
    case Sha384 = 'sha384';
    case Sha512 = 'sha512';

    /**
     * Return the expected hex-encoded HMAC length for this algorithm.
     */
    public function hexLength(): int
    {
        return match ($this) {
            self::Sha256 => 64,
            self::Sha384 => 96,
            self::Sha512 => 128,
        };
    }
}
