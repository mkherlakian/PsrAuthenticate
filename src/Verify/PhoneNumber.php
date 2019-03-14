<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Verify;

use Ramsey\Uuid\Uuid;
use Assert\Assertion;

class PhoneNumber
{
    public static function fromNumber(string $number)
    {
        //verify?
        Assertion::regex($number, '/^\+([0-9]\ ?){6,14}[0-9]$/');

        $self = new self($number);
        return $self;

    }

    private function __construct($number)
    {
        $this->number = $number;
    }

    public function toString() : string
    {
        return $this->number;
    }
}
