<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response\JsonResponse;
use Mauricek\PsrAuthentication\Authenticate;
use Mauricek\PsrAuthentication\Credentials;
use Mauricek\PsrAuthentication\AuthResult;
use Mauricek\PsrAuthentication\LoginValidator;
use Mauricek\PsrAuthentication\Exception\RuntimeException;

class LogoutHandler implements RequestHandlerInterface
{
    protected $authenticate;

    public function  __construct(
        Authenticate $authenticate
    ) {
        $this->authenticate = $authenticate;
    }

    public function handle(ServerRequestInterface $request) : ResponseInterface
    {
        $credentials = $request
            ->getAttribute(Credentials::class);

        if(!$credentials || !$credentials instanceof Credentials) {
            throw new RuntimeException('No credentials found');
        }

        $authResult = $this->authenticate->logout($credentials->memberId());

        if($authResult->success())
        {
            return new JsonResponse([
                'status' => 'success'
            ]);
        }

        throw new RuntimeException('Unauthorized logout attempt');
    }
}
