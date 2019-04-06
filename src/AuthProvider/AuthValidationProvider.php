<?php

namespace Mauricek\PsrAuthentication\AuthProvider;

use Psr\Http\Message\ServerRequestInterface;
use Mauricek\PsrAuthentication\Credentials;

interface AuthValidationProvider
{
    public function validate(ServerRequestInterface $request) : ?Credentials;
    public function additionalParameters() : array;
}
