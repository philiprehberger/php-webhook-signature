<?php

declare(strict_types=1);

namespace PhilipRehberger\WebhookSignature\Exceptions;

/**
 * Thrown when a webhook signature is valid but its timestamp has exceeded
 * the allowed tolerance window, indicating a potential replay attack.
 */
class SignatureExpiredException extends InvalidSignatureException
{
    public function __construct(string $message = 'Webhook signature has expired and may be a replay attack.', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
