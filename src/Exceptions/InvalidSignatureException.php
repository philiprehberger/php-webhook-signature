<?php

declare(strict_types=1);

namespace PhilipRehberger\WebhookSignature\Exceptions;

/**
 * Thrown when a webhook signature fails verification.
 *
 * Use this when you prefer exception-based flow control over
 * checking boolean return values from WebhookSignature::verify().
 */
class InvalidSignatureException extends \RuntimeException
{
    public function __construct(string $message = 'Webhook signature verification failed.', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
