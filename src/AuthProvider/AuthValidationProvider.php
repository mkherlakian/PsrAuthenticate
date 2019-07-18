<?php

namespace Mauricek\PsrAuthentication\AuthProvider;

use Psr\Http\Message\ServerRequestInterface;
use Mauricek\PsrAuthentication\Credentials;

interface AuthValidationProvider
{
    public function validate(ServerRequestInterface $request) : ?Credentials;

    /**
     * Additional parameters that we want the request to carry forward
     */
    public function additionalParameters() : array;
}
