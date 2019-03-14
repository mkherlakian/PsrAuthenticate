<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication;

class TokenJti
{
    public function __construct(string $jti)
    {
        $this->jti = $jti;
    }

    public function jti() : string
    {
        return $this->jti;
    }
}
