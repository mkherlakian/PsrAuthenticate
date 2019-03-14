<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication;

interface CanHashPassword
{
    public function hash(string $password) : string;
    public function verify(string $password, string $hash) : bool;
}
