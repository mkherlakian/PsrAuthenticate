<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Mauricek\PsrAuthentication\Authenticate;
use Mauricek\PsrAuthentication\Credentials;
use Mauricek\PsrAuthentication\AuthResult;
use Mauricek\PsrAuthentication\LoginValidator;
use Mauricek\PsrAuthentication\Exception;

class LoginMiddleware implements MiddlewareInterface
{
    protected $authenticate;

    public function  __construct(
        Authenticate $authenticate,
        LoginValidator $loginValidator

    ) {
        $this->authenticate = $authenticate;
        $this->validator    = $loginValidator;
    }

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $delegate
    ) : ResponseInterface {

        $body = $request->getParsedBody();

        $input = [];

        isset($body['email'])       && $input['email']      = filter_var($body['email'],    FILTER_SANITIZE_EMAIL);
        isset($body['password'])    && $input['password']   = filter_var($body['password'], FILTER_SANITIZE_STRING);

        $valid = $this->validator->validate($input);

        if(!$valid)
        {
            $messages = implode(', ', $this->validator->getMessages());
            throw new Exception\InvalidArgumentException("Validation - $messages");
        }

        $ip             = $request->getServerParams()['REMOTE_ADDR'];
        $fingerprint    = 'some_fingerprint';

        $authResult = $this->authenticate->login(
            $input['email'],
            $input['password']
        );

        if(!$authResult->success())
        {
            throw new Exception\RuntimeException('Unauthtorized login attempt - '.$authResult->reason());
        }

        $credentials = new Credentials(
            $authResult->member()->id(),
            $authResult->member()->username(),
            $authResult->role(),
            $authResult->refreshToken()
        );

        $request = $request->withAttribute(Credentials::class, $credentials);

        return $delegate->handle($request);
    }
}
