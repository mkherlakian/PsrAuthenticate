<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Verify;

use Assert\Assertion;

class Email
{
    private $email;

    public static function fromAddress(string $email)
    {
        Assertion::email($email);

        $self = new self($email);
        return $self;
    }

    private function __construct(string $email)
    {
        $this->email = $email;
    }

    public function toString()
    {
        return $this->email;
    }
}
