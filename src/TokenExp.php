<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication;

class TokenExp
{
    public function __construct(int $exp)
    {
        $this->exp = $exp;
    }

    public function exp() : int
    {
        return $this->exp;
    }
}
